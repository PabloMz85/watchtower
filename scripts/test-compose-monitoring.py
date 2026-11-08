#!/usr/bin/env python3
"""Exercise the demo's real auth/config in isolated Docker resources.

Requires Python 3, Docker Compose, prom/prometheus and a locally built
watchtower:local (override with --watchtower-image). Never starts the demo.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]


def run(*args, env=None):
    result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=120)
    if result.returncode:
        # Do not echo command/env/config: they may contain credentials.
        raise RuntimeError(f"{args[0]} {args[1]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def request(url, token=None):
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(urllib.request.Request(url, headers=headers), timeout=3) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def wait_for(probe, message, seconds=40):
    deadline = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = probe()
            if value:
                return value
        except (OSError, ValueError) as error:
            # Services may still be starting; retain the last failure for timeout diagnostics.
            last_error = error
        time.sleep(0.5)
    raise AssertionError(message) from last_error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watchtower-image", default="watchtower:local")
    args = parser.parse_args()
    require(bool(args.watchtower_image) and not args.watchtower_image.startswith("-")
            and not any(character.isspace() or ord(character) < 32 for character in args.watchtower_image),
            "Invalid Watchtower image reference")
    token = secrets.token_urlsafe(40) + "+/="
    env = dict(os.environ, WATCHTOWER_HTTP_API_TOKEN=token)
    config = json.loads(run("docker", "compose", "--env-file", os.devnull,
                            "-f", str(ROOT / "docker-compose.yml"),
                            "config", "--format", "json", env=env))
    services = config["services"]
    require(services["watchtower"]["environment"]["WATCHTOWER_HTTP_API_TOKEN"] == token, "Watchtower must receive the external token")
    require(all(port.get("host_ip") == "127.0.0.1"
                for port in services["watchtower"].get("ports", [])), "Watchtower API must stay on loopback")
    require(not services["prometheus"].get("user"), "Keep the Prometheus image's default user")
    image = services["prometheus"]["image"]
    image_user = run("docker", "image", "inspect", image, "--format", "{{.Config.User}}")
    require(image_user not in ("", "root", "0", "0:0"), "Prometheus image must default to non-root")
    print(f"Prometheus image={run('docker', 'image', 'inspect', image, '--format', '{{.Id}}')} user={image_user}", flush=True)
    handle = "wt-auth-" + secrets.token_hex(6)
    network = handle + "-net"
    names = []
    volume_names = []
    network_created = False
    print(f"Runtime handles: network={network}; containers={handle}-watchtower,{handle}-prometheus", flush=True)
    try:
        run("docker", "network", "create", "--label", "watchtower.auth-test=" + handle, network)
        network_created = True
        urls = {}
        for service_name, port in (("watchtower", 8080), ("prometheus", 9090)):
            service = services[service_name]
            name = handle + "-" + service_name
            create = ["docker", "create", "--name", name, "--label", "watchtower.auth-test=" + handle,
                      "--network", network, "--network-alias", service_name,
                      "--publish", f"127.0.0.1::{port}"]
            child_env = dict(os.environ)
            for key, value in service.get("environment", {}).items():
                child_env[key] = value
                create += ["--env", key]
            for volume in service.get("volumes", []):
                if volume["type"] == "bind":
                    spec = f"type=bind,source={volume['source']},target={volume['target']}"
                    if volume.get("read_only"):
                        spec += ",readonly"
                    create += ["--mount", spec]
                elif volume["type"] == "volume":
                    # Anonymous test-only data, never the demo's named volumes.
                    create += ["--volume", volume["target"]]
                else:
                    raise AssertionError("Unsupported demo mount type")
            entrypoint = service.get("entrypoint") or []
            command = service.get("command") or []
            require(isinstance(entrypoint, list) and isinstance(command, list), "Entrypoint and command must be argument lists")
            if entrypoint:
                create += ["--entrypoint", entrypoint[0]]
            if service_name == "watchtower":
                # Non-matching scope/name plus no-pull/monitor-only protects every
                # existing service, even though the real Docker socket is used.
                command = ["--scope", handle, "--interval", "3600", "--monitor-only",
                           "--no-pull", "--http-api-metrics", handle + "-no-target"]
            create += [args.watchtower_image if service_name == "watchtower" else image]
            create += entrypoint[1:] + command
            run(*create, env=child_env)
            names.append(name)
            details = json.loads(run("docker", "inspect", name))[0]
            volume_names.extend(mount["Name"] for mount in details["Mounts"] if mount["Type"] == "volume")
            run("docker", "start", name)
            binding = json.loads(run("docker", "inspect", name))[0]["NetworkSettings"]["Ports"][f"{port}/tcp"][0]
            require(binding["HostIp"] == "127.0.0.1", "Published address must be loopback")
            host_port = binding["HostPort"]
            if not isinstance(host_port, str) or not host_port.isascii() or not host_port.isdecimal() or not 1 <= int(host_port) <= 65535:
                raise AssertionError("Docker returned an invalid published port")
            urls[service_name] = f"http://127.0.0.1:{int(host_port)}"
        metrics = urls["watchtower"] + "/v1/metrics"
        wait_for(lambda: request(metrics, token)[0] == 200, "non-demo token did not authenticate")
        require(request(metrics)[0] == 401, "missing token must be rejected")
        require(request(metrics, token + "wrong")[0] == 401, "wrong token must be rejected")
        require(request(metrics, "demotoken")[0] == 401, "old demo token must be rejected")
        print("PASS metrics: generated non-demo token HTTP 200; missing/wrong/old demo token HTTP 401", flush=True)
        query = urls["prometheus"] + "/api/v1/query?" + urllib.parse.urlencode({"query": 'up{job="watchtower"}'})
        last = {}

        def scraped():
            status, body = request(query)
            if status != 200:
                return False
            data = json.loads(body)
            last["result"] = data.get("data", {}).get("result", [])
            return len(last["result"]) == 1 and last["result"][0]["value"][1] == "1"

        try:
            wait_for(scraped, "Prometheus did not scrape Watchtower with the external token", seconds=25)
        except AssertionError:
            status, body = request(urls["prometheus"] + "/api/v1/targets")
            errors = [target.get("lastError") for target in json.loads(body).get("data", {}).get("activeTargets", [])] if status == 200 else []
            raise AssertionError(f"Prometheus scrape failed: up={last.get('result')}; errors={errors}") from None
        print('PASS Prometheus: up{job="watchtower"}=1', flush=True)
        status, body = request(urls["prometheus"] + "/api/v1/status/config")
        require(status == 200 and token not in body, "Prometheus config API must not expose the credential")
        print("PASS Prometheus: config API does not expose the credential", flush=True)
        # For the private-file setup also verify actual owner/modes and PID 1's
        # inherited environment. Read no secret bytes into the test output.
        if "bearer_token_file:" in (ROOT / "prometheus/prometheus.yml").read_text():
            check = 'test "$(id -u)" != 0; test "$(stat -c %a /tmp/watchtower-auth)" = 700; test "$(stat -c %a /tmp/watchtower-auth/token)" = 600; test "$(stat -c %u /tmp/watchtower-auth/token)" = "$(id -u)"; ! tr "\\000" "\\n" < /proc/1/environ | grep -q "^WATCHTOWER_HTTP_API_TOKEN="'
            run("docker", "exec", names[1], "/bin/sh", "-ec", check)
            print("PASS Prometheus: non-root; private token directory 0700/file 0600 owned by runtime UID; token absent from PID 1 environment", flush=True)
    finally:
        cleanup_errors = []
        for name in reversed(names):
            try:
                details = json.loads(run("docker", "inspect", name))[0]
                if details["Config"].get("Labels", {}).get("watchtower.auth-test") != handle:
                    raise AssertionError("Refusing cleanup of a container not owned by this test")
                run("docker", "stop", "--time", "5", name)
                run("docker", "rm", "--volumes", name)
                result = subprocess.run(["docker", "inspect", name], capture_output=True, timeout=20)
                require(result.returncode != 0, f"Container left behind: {name}")
            except (RuntimeError, AssertionError) as error:
                cleanup_errors.append(str(error))
        for volume_name in volume_names:
            result = subprocess.run(["docker", "volume", "inspect", volume_name], capture_output=True, timeout=20)
            if result.returncode == 0:
                cleanup_errors.append(f"Anonymous data volume left behind: {volume_name}")
        if network_created:
            try:
                run("docker", "network", "rm", network)
                result = subprocess.run(["docker", "network", "inspect", network], capture_output=True, timeout=20)
                require(result.returncode != 0, f"Network left behind: {network}")
            except (RuntimeError, AssertionError) as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            raise RuntimeError("Cleanup failed: " + "; ".join(cleanup_errors))
        print("PASS cleanup: exact test containers, anonymous data volumes and network removed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
