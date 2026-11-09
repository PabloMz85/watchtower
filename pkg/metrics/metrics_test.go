package metrics

import (
	"reflect"
	"testing"
	"testing/synctest"

	"github.com/PabloMz85/watchtower/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

// Unexpected report methods panic through the embedded interface.
type metricReport struct {
	types.Report
	scanned, updated, failed, stale []types.ContainerReport
}

func (r metricReport) Scanned() []types.ContainerReport { return r.scanned }
func (r metricReport) Updated() []types.ContainerReport { return r.updated }
func (r metricReport) Failed() []types.ContainerReport  { return r.failed }
func (r metricReport) Stale() []types.ContainerReport   { return r.stale }

func TestNewMetricReportCounts(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		scanned, updated, failed, stale int
		want                            Metric
	}{
		{name: "empty"},
		{name: "all counts", scanned: 8, updated: 2, failed: 3, stale: 1, want: Metric{Scanned: 8, Updated: 3, Failed: 3}},
		{name: "stale counts as updated for compatibility", stale: 4, want: Metric{Updated: 4}},
		{name: "scanned is not recomputed from other counts", scanned: 7, updated: 1, want: Metric{Scanned: 7, Updated: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := metricReport{
				scanned: make([]types.ContainerReport, tc.scanned),
				updated: make([]types.ContainerReport, tc.updated),
				failed:  make([]types.ContainerReport, tc.failed),
				stale:   make([]types.ContainerReport, tc.stale),
			}
			if got := NewMetric(report); got == nil || *got != tc.want {
				t.Fatalf("metric = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func assertMetrics(t *testing.T, registry *prometheus.Registry, scanned, updated, failed, total, skipped float64) {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]float64)
	for _, family := range families {
		if len(family.Metric) != 1 {
			t.Fatalf("%s contains %d metrics, want 1", family.GetName(), len(family.Metric))
		}
		metric := family.Metric[0]
		if metric.Gauge != nil {
			got[family.GetName()] = metric.Gauge.GetValue()
		} else if metric.Counter != nil {
			got[family.GetName()] = metric.Counter.GetValue()
		} else {
			t.Fatalf("unexpected metric type: %s", family.GetName())
		}
	}
	want := map[string]float64{
		"watchtower_containers_scanned": scanned,
		"watchtower_containers_updated": updated,
		"watchtower_containers_failed":  failed,
		"watchtower_scans_total":        total,
		"watchtower_scans_skipped":      skipped,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collected metrics = %v, want %v", got, want)
	}
}

func TestRegisterQueueAndHandleUpdate(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := &Metrics{
		channel: make(chan *Metric, 3),
		scanned: prometheus.NewGauge(prometheus.GaugeOpts{Name: "watchtower_containers_scanned"}),
		updated: prometheus.NewGauge(prometheus.GaugeOpts{Name: "watchtower_containers_updated"}),
		failed:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "watchtower_containers_failed"}),
		total:   prometheus.NewCounter(prometheus.CounterOpts{Name: "watchtower_scans_total"}),
		skipped: prometheus.NewCounter(prometheus.CounterOpts{Name: "watchtower_scans_skipped"}),
	}
	registry.MustRegister(m.scanned, m.updated, m.failed, m.total, m.skipped)
	if !m.QueueIsEmpty() {
		t.Fatal("new queue is not empty")
	}
	first := &Metric{Scanned: 8, Updated: 5, Failed: 2}
	m.Register(first)
	if m.QueueIsEmpty() {
		t.Fatal("registered scan was not queued")
	}
	if got := <-m.channel; got != first {
		t.Fatalf("Register queued %p, want %p", got, first)
	}
	m.Register(first)
	close(m.channel)
	m.HandleUpdate(m.channel)
	if !m.QueueIsEmpty() {
		t.Fatal("processed queue is not empty")
	}
	assertMetrics(t, registry, 8, 5, 2, 1, 0)

	// A skipped scan increments both counters and clears the previous gauges.
	changes := make(chan *Metric, 1)
	changes <- nil
	close(changes)
	m.HandleUpdate(changes)
	assertMetrics(t, registry, 0, 0, 0, 2, 1)

	changes = make(chan *Metric, 2)
	changes <- &Metric{Scanned: 10, Updated: 7, Failed: 4}
	changes <- &Metric{Scanned: 3, Updated: 1}
	close(changes)
	m.HandleUpdate(changes)
	assertMetrics(t, registry, 3, 1, 0, 4, 1)
}

func TestDefaultCollectorsAndRegisterScan(t *testing.T) {
	// The bubble joins the production worker on return and detects leaks/deadlocks.
	synctest.Test(t, func(t *testing.T) {
		previous, registerer, gatherer := metrics, prometheus.DefaultRegisterer, prometheus.DefaultGatherer
		registry := prometheus.NewRegistry()
		metrics = nil
		prometheus.DefaultRegisterer = registry
		prometheus.DefaultGatherer = registry
		t.Cleanup(func() {
			metrics = previous
			prometheus.DefaultRegisterer = registerer
			prometheus.DefaultGatherer = gatherer
		})

		m := Default()
		t.Cleanup(func() {
			close(m.channel)
			synctest.Wait()
		})
		if Default() != m {
			t.Fatal("Default did not reuse the singleton")
		}
		if cap(m.channel) != 10 || !m.QueueIsEmpty() {
			t.Fatalf("default queue capacity/empty = %d/%t, want 10/true", cap(m.channel), m.QueueIsEmpty())
		}
		assertMetrics(t, registry, 0, 0, 0, 0, 0)
		RegisterScan(&Metric{Scanned: 6, Updated: 2, Failed: 1})
		synctest.Wait()
		if !m.QueueIsEmpty() {
			t.Fatal("default worker did not drain the queue")
		}
		assertMetrics(t, registry, 6, 2, 1, 1, 0)
		RegisterScan(nil)
		synctest.Wait()
		assertMetrics(t, registry, 0, 0, 0, 2, 1)
		RegisterScan(&Metric{Scanned: 1})
		synctest.Wait()
		assertMetrics(t, registry, 1, 0, 0, 3, 1)
	})
}
