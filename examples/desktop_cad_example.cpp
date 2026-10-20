/**
 * LicenseFlow C++20 Desktop CAD & Gaming Native Example
 * =====================================================
 * Demonstrates:
 * 1. Weighted multi-tier hardware fingerprinting (CPU + Board + Disk + MAC)
 * 2. In-memory lock-free verification suitable for 120 FPS render loops
 * 3. Offline Ed25519 .lic verification for air-gapped workstations
 * 4. Background real-time revocation streaming & emergency kill-switch trip
 */

#include "licenseflow/licenseflow.hpp"
#include <iostream>
#include <cassert>
#include <chrono>

int main() {
    std::cout << "[LicenseFlow C++] Initializing Desktop CAD Suite...\n";

    // 1. Generate weighted hardware fingerprint
    std::string hw_id = licenseflow::get_weighted_hardware_fingerprint();
    std::cout << "[Hardware] Machine composite binding: " << hw_id << "\n";
    assert(!hw_id.empty());

    // 2. Initialize Client
    licenseflow::Client client("lf_live_mock_desktop_key_2026");

    // 3. Online / Cached Verification
    auto res = client.verify("LF-CAD-PRO-9981-XXXX");
    std::cout << "[License] Verified status: " << res.status 
              << ", valid: " << (res.valid ? "true" : "false") << "\n";
    assert(res.valid == true);

    // 4. Feature check
    bool has_export = client.has_feature(res, "cad_export");
    std::cout << "[Entitlement] 4K CAD Export: " << (has_export ? "ENABLED" : "DISABLED") << "\n";

    // 5. Offline Ed25519 .lic Token Verification
    std::cout << "\n[Air-Gap] Testing offline .lic verification...\n";
    std::string mock_lic_content = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.payload.signature";
    auto offline_res = client.verify_offline_license(mock_lic_content, "AutoCAD Enterprise 2026");
    std::cout << "[Air-Gap] Product: " << offline_res.product_name 
              << ", Offline Unlocked: " << (offline_res.features["offline_unlocked"] ? "YES" : "NO") << "\n";
    assert(offline_res.valid == true);

    // 6. Zero-latency Render Loop Check & Emergency Kill Switch
    std::cout << "\n[Render Loop] Emulating 120 FPS zero-latency check...\n";
    auto t0 = std::chrono::high_resolution_clock::now();
    bool revoked = client.is_revoked("engineer@cadcorp.com", "LF-CAD-PRO-9981-XXXX");
    auto t1 = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
    std::cout << "[Perf] Render loop access check latency: " << ns << " ns (Revoked: " << (revoked ? "YES" : "NO") << ")\n";

    // 7. Trip Local Kill Switch
    std::cout << "[Kill-Switch] Tripping emergency revocation for LF-CAD-PRO-9981-XXXX...\n";
    client.trip_kill_switch_local("license", "LF-CAD-PRO-9981-XXXX", "Policy: Security audit violation");
    std::string reason;
    bool is_now_revoked = client.is_revoked("", "LF-CAD-PRO-9981-XXXX", "", &reason);
    std::cout << "[Kill-Switch] License Revoked: " << (is_now_revoked ? "YES" : "NO") 
              << " (Reason: " << reason << ")\n";
    assert(is_now_revoked == true);

    std::cout << "\n[LicenseFlow C++] All desktop native gaming & CAD parity tests passed successfully.\n";
    return 0;
}
