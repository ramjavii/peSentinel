rule pesentinel_test_marker
{
    meta:
        description = "Synthetic test rule for peSentinel"
        family = "TestMarker"
        severity = "high"
    strings:
        $marker = "PESENTINEL_TEST_MALWARE_MARKER"
    condition:
        $marker
}
