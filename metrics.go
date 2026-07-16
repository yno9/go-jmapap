package main

import "github.com/prometheus/client_golang/prometheus"

// Relay-specific metrics for the ActivityPub relay. Registered into the shared
// jmapserver metrics registry via RegisterMetrics(..., relayCollectors()...).
var (
	apOutbound = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "biset_ap_outbound_total",
		Help: "Outbound ActivityPub HTTP-signed deliveries, by result.",
	}, []string{"result"})
	apSignature = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "biset_ap_signature_verifications_total",
		Help: "Inbound HTTP signature verifications, by result.",
	}, []string{"result"})
	apInbox = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "biset_ap_inbox_activities_total",
		Help: "Inbound ActivityPub activities, by type. Bounded to Accept/Create, the standard unhandled types in knownUnhandledType, and 'other'.",
	}, []string{"type"})
)

// relayCollectors returns the AP-specific collectors and pre-initializes known
// label series to 0 so they are present before the first event.
func relayCollectors() []prometheus.Collector {
	apOutbound.WithLabelValues("ok")
	apOutbound.WithLabelValues("failed")
	apSignature.WithLabelValues("ok")
	apSignature.WithLabelValues("failed")
	apInbox.WithLabelValues("Accept")
	apInbox.WithLabelValues("Create")
	for t := range knownUnhandledType {
		apInbox.WithLabelValues(t)
	}
	apInbox.WithLabelValues("other")
	return []prometheus.Collector{apOutbound, apSignature, apInbox}
}
