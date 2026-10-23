// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

type logShutdownStatus struct {
	Lines    int  `json:"lines"`
	Blocked  bool `json:"blocked"`
	Enriched bool `json:"enriched"`
	Paused   bool `json:"paused"`
}

func logShutdownRequest(url string) (logShutdownStatus, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return logShutdownStatus{}, err
	}
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.Close = true
	httpClient := http.Client{Timeout: 2 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return logShutdownStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return logShutdownStatus{}, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	var status logShutdownStatus
	err = json.NewDecoder(resp.Body).Decode(&status)
	return status, err
}

func testLogEnricherNodeJSShutdown(t *testing.T, compose *docker.Compose) {
	const (
		workloadURL = "http://localhost:8383"
		stalledURL  = "http://localhost:8384"
		readerURL   = "http://localhost:8385"
		warmup      = time.Minute
		minimumLogs = 64 * 1024
	)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := logShutdownRequest(workloadURL + "/marker")
		require.NoError(ct, err)
		logs, err := compose.LogsTail(20, "workload")
		require.NoError(ct, err)
		assert.Contains(ct, logs, `"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`)

		_, err = logShutdownRequest(stalledURL + "/marker")
		require.NoError(ct, err)
		reader, err := logShutdownRequest(readerURL + "/status")
		require.NoError(ct, err)
		assert.True(ct, reader.Enriched, "the FIFO writer must also be enriched")
	}, time.Minute, time.Second)

	// Resume before Compose teardown, including when a regression leaves a
	// live shard blocked or ContainerStop waiting for the application's logs.
	t.Cleanup(func() {
		_, err := logShutdownRequest(readerURL + "/resume")
		assert.NoError(t, err)
	})
	if !t.Run("Backpressure", func(t *testing.T) {
		_, err := logShutdownRequest(readerURL + "/pause")
		require.NoError(t, err)
		_, err = logShutdownRequest(stalledURL + "/burst")
		require.NoError(t, err)
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			status, err := logShutdownRequest(stalledURL + "/status")
			require.NoError(ct, err)
			assert.True(ct, status.Blocked)
		}, 10*time.Second, 100*time.Millisecond)
		_, err = logShutdownRequest(workloadURL + "/backpressure")
		require.NoError(t, err)
		// Keep the live shard stalled long enough to expose per-write expiry.
		time.Sleep(2 * time.Second)
		logs, err := compose.LogsTail(20, "workload")
		require.NoError(t, err)
		require.NotContains(t, logs, `"message":"backpressure marker"`)
		_, err = logShutdownRequest(readerURL + "/resume")
		require.NoError(t, err)
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			logs, err := compose.LogsTail(20, "workload")
			require.NoError(ct, err)
			assert.Contains(ct, logs, `"message":"backpressure marker"`)
		}, 10*time.Second, 100*time.Millisecond)
	}) {
		return
	}

	t.Run("Shutdown", func(t *testing.T) {
		for _, url := range []string{workloadURL, stalledURL} {
			_, err := logShutdownRequest(url + "/start")
			require.NoError(t, err)
		}
		started := time.Now()
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			for _, url := range []string{workloadURL, stalledURL} {
				status, err := logShutdownRequest(url + "/status")
				require.NoError(ct, err)
				assert.GreaterOrEqual(ct, status.Lines, minimumLogs)
			}
			assert.GreaterOrEqual(ct, time.Since(started), warmup)
		}, 3*warmup, time.Second)
		t.Logf("each application wrote at least %d log lines over %s", minimumLogs, time.Since(started))

		reader, err := logShutdownRequest(readerURL + "/pause")
		require.NoError(t, err)
		require.True(t, reader.Paused)
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			status, err := logShutdownRequest(stalledURL + "/status")
			require.NoError(ct, err)
			assert.True(ct, status.Blocked, "the FIFO must fill before shutdown")
		}, 10*time.Second, 100*time.Millisecond)

		before, err := logShutdownRequest(workloadURL + "/status")
		require.NoError(t, err)
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			status, err := logShutdownRequest(workloadURL + "/status")
			require.NoError(ct, err)
			assert.GreaterOrEqual(ct, status.Lines, before.Lines+1024,
				"queue workload logs behind the stalled destination")
		}, 10*time.Second, 100*time.Millisecond)

		cl, err := client.New(client.FromEnv)
		require.NoError(t, err)
		defer cl.Close()
		id := testContainerID(t, cl, "hatest-testserver-logenricher-shutdown")
		require.NotEmpty(t, id)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		graceSeconds := 30 // longer than the API deadline, so SIGKILL cannot make the test pass
		startStop := time.Now()
		_, err = cl.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &graceSeconds})
		require.NoError(t, err, "container log drain held shutdown after SIGTERM")
		t.Logf("container stopped in %s after sustained logging and a stalled reader", time.Since(startStop))
		inspect, err := cl.ContainerInspect(t.Context(), id, client.ContainerInspectOptions{})
		require.NoError(t, err)
		require.False(t, inspect.Container.State.Running)
		require.Zero(t, inspect.Container.State.ExitCode, "Node.js must exit cleanly, without SIGKILL")
	})
}
