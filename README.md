<div align="center">

  ### Fork with updated Docker Engine API support
  The original upstream project is no longer maintained.
  This fork uses the supported Moby client/API modules and automatic API version negotiation.

  ---
  
  <img src="./logo.png" width="450" />
  
  # Watchtower
  
  A process for automating Docker container base image updates.
  <br/><br/>
  
  [![Circle CI](https://circleci.com/gh/PabloMz85/watchtower.svg?style=shield)](https://circleci.com/gh/PabloMz85/watchtower)
  [![codecov](https://codecov.io/gh/PabloMz85/watchtower/branch/main/graph/badge.svg)](https://codecov.io/gh/PabloMz85/watchtower)
  [![GoDoc](https://godoc.org/github.com/PabloMz85/watchtower?status.svg)](https://godoc.org/github.com/PabloMz85/watchtower)
  [![Go Report Card](https://goreportcard.com/badge/github.com/PabloMz85/watchtower)](https://goreportcard.com/report/github.com/PabloMz85/watchtower)
  [![latest version](https://img.shields.io/github/tag/PabloMz85/watchtower.svg)](https://github.com/PabloMz85/watchtower/releases)
  [![Apache-2.0 License](https://img.shields.io/github/license/PabloMz85/watchtower.svg)](https://www.apache.org/licenses/LICENSE-2.0)
  [![Codacy Badge](https://app.codacy.com/project/badge/Grade/1c48cfb7646d4009aa8c6f71287670b8)](https://www.codacy.com/gh/PabloMz85/watchtower/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=PabloMz85/watchtower&amp;utm_campaign=Badge_Grade)
  [![All Contributors](https://img.shields.io/github/all-contributors/PabloMz85/watchtower)](#contributors)
  [![Pulls from DockerHub](https://img.shields.io/docker/pulls/PabloMz85/watchtower.svg)](https://hub.docker.com/r/PabloMz85/watchtower)

</div>

## Build this fork

Requirements: Go 1.27.3 or newer, or Docker with BuildKit. The Docker daemon must support API 1.40 or newer. Containers retaining a legacy container-wide `Config.MacAddress` are deliberately excluded from automatic recreation rather than risk changing their MAC; see [configuration-preservation boundaries](docs/docker-api-upgrade.md#configuration-preservation-boundaries).

```sh
go test ./...
go build -o watchtower .
WATCHTOWER_INTEGRATION=1 bash scripts/verify.sh
docker build -f dockerfiles/Dockerfile.self-contained -t watchtower:local .
```

Both self-contained Dockerfiles build and test the **local checkout**, not an upstream clone. No registry publishing is performed by these commands.

### Multi-platform image from source

Run from the repository root (`/Users/pablo/projects/watchtower`), with the repository root as the final build-context argument:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f dockerfiles/Dockerfile.self-contained \
  --build-arg WATCHTOWER_VERSION=0.0.1 \
  -t pablomz85/watchtower:0.0.1 \
  --load \
  .
```

This builds a separate Linux executable for each target architecture and sets the application version to `0.0.1`. The command loads the image locally; it does not push to a registry. Loading both architectures requires a Docker image store with multi-platform support, as used by the verified Docker Desktop build.

`dockerfiles/Dockerfile` is the **release-packaging** Dockerfile used by GoReleaser. It expects an already compiled, architecture-specific Linux executable named `watchtower` in its build context. It does not compile the source. Using `./dockerfiles/` as context fails because that directory contains no executable; using the root context with that packaging Dockerfile is also not the source-build path, because `.dockerignore` intentionally excludes local executables. Do not remove those exclusions or copy a macOS/single-architecture binary into a multi-platform image. Use a self-contained Dockerfile with the root context for source builds.

Do not set `DOCKER_API_VERSION` or `--api-version` unless an exact version is required. Remove old pins such as `1.25` from Compose or environment files; an explicit `--api-version=` also restores negotiation. See [Docker API version](docs/arguments.md#docker-api-version).

For a non-mutating connectivity check, use an explicit container name and disable pulls:

```sh
docker run --rm \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  watchtower:local --run-once --monitor-only --no-pull your-container-name
```

The Docker socket grants control over the daemon, even with a read-only bind mount. Only run trusted images with that access. The connectivity check does not replace testing an actual update in an isolated environment. Full scan failures exit with status 1 instead of panicking or reporting success.

The root `docker-compose.yml` is an optional monitoring demo, not a production deployment. It requires `WATCHTOWER_HTTP_API_TOKEN` from your environment or secret manager and binds the Watchtower API to localhost; it no longer supplies a shared demo token. Compose passes the same token to Watchtower and Prometheus. Prometheus keeps its image's default non-root user and writes a private runtime bearer-token file (directory mode `0700`, file mode `0600`), rather than storing the token in the scrape configuration. Treat container inspection and rendered `docker compose config` output as sensitive because the token is supplied through container environment variables. Recreate both services when rotating the token.

After building `watchtower:local` and pulling the Compose Prometheus image (`docker pull prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06`), run `python3 scripts/test-compose-monitoring.py` to verify authentication and an actual Prometheus scrape with a generated non-demo token. The test uses unique container/network names, anonymous data volumes, loopback-only random ports, and a non-matching Watchtower scope with monitor-only/no-pull; it never launches the demo or targets existing services. It prints runtime handles and removes only its own resources, including on failure.

## Quick Start

With watchtower you can update the running version of your containerized app simply by pushing a new image to the Docker Hub or your own image registry. 

Watchtower will pull down your new image, gracefully shut down your existing container and restart it with the same options that were used when it was deployed initially. Run the watchtower container with the following command:

```
$ docker run --detach \
    --name watchtower \
    --volume /var/run/docker.sock:/var/run/docker.sock \
    watchtower:local
```

Watchtower is intended to be used in homelabs, media centers, local dev environments, and similar. We do **not** recommend using Watchtower in a commercial or production environment. If that is you, you should be looking into using Kubernetes. If that feels like too big a step for you, please look into solutions like [MicroK8s](https://microk8s.io/) and [k3s](https://k3s.io/) that take away a lot of the toil of running a Kubernetes cluster. 

## Documentation
The full documentation is available at https://containrrr.dev/watchtower.

## Contributors

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://piksel.se"><img src="https://imgs.search.brave.com/CGdEFN2cTkOmbc4qBAVbyIznGS3ojVHDBBrKD4HRnUw/rs:fit:860:0:0:0/g:ce/aHR0cHM6Ly9tZWRp/YS5pc3RvY2twaG90/by5jb20vaWQvNTgz/Nzk1Mjg0L2RlL2Zv/dG8vYXJnZW50aW5p/ZW4tbWl0LWZsYWdn/ZS1hdWYtZGVyLWth/cnRlLWdlcGlubnQu/anBnP3M9NjEyeDYx/MiZ3PTAmaz0yMCZj/PUZFQUMxUWJmdFUx/eU5wREYyUl9pMF93/MXZldTR5cmZZdU5N/YzI2Umh2eVU9?v=4?s=100" width="100px;" alt="PabloMz"/><br /><sub><b>PabloMz</b></sub></a><br /><a href="https://github.com/PabloMz85/watchtower/commits?author=PabloMz85" title="Code">💻</a> <a href="https://github.com/PabloMz85/watchtower/commits?author=PabloMz85" title="Documentation">📖</a> <a href="#maintenance-PabloMz85" title="Maintenance">🚧</a> <a href="https://github.com/PabloMz85/watchtower/pulls?q=is%3Apr+reviewed-by%PabloMz85" title="Reviewed Pull Requests">👀</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
