// Stub for the warmup() timing helper used by the vendored LaBRADOR test
// harness. Upstream builds it from warmup.S, which is not shipped in the
// submodule; it only warms the clock for cycle measurements, so an empty
// body is fine for functional testing under an emulator.
void warmup(void) {}
