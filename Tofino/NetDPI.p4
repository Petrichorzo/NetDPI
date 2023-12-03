
#include <core.p4>
#include <tna.p4>


#include "filter.p4"
#include "verifier.p4"

#include "headers.p4"




// Packet comes into ingress profile_a which adds an extra custom_metadata_h
// header to the packet. The packet travels to egress profile_b, then to
// ingress profile_b and finally to egress profile_a. The custom_metadata_h
// header is striped off by egress profile_b. Value of custom_tag is modified
// as the packet travels.

Pipeline(IngressParser_filter(),
         Ingress_filter(),
         IngressDeparser_filter(),
         EgressParser_filter(),
         Egress_filter(),
         EgressDeparser_filter()) pipeline_profile_filter;

Pipeline(IngressParser_verifier(),
         Ingress_verifier(),
         IngressDeparser_verifier(),
         EgressParser_verifier(),
         Egress_verifier(),
         EgressDeparser_verifier()) pipeline_profile_verifier;

Switch(pipeline_profile_filter, pipeline_profile_verifier) main;