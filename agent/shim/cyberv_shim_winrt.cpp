// CyberV WinRT Shim — WiFi Direct (M-3, Tier B) + BLE advertisement (M-4, Tier C)
//
// Ref: Docs/HYBRID_DISTRIBUTION_PLAN.md §1.1 + Docs/TRANSPORT_ISOLATION_PLAN.md
// M-3/M-4. Quy tắc §1.1: ABI extern "C" thuần, KHÔNG business logic (chỉ
// transliterate WinRT API — logic nằm Rust), không C++ object/exception qua
// biên giới (catch-all → mã lỗi), bộ nhớ một chiều (Rust cấp buffer).
// Không dependency C++ bên thứ ba — std + WinRT projection của SDK.

#include "cyberv_shim.h"

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Devices.Enumeration.h>
#include <winrt/Windows.Devices.WiFiDirect.h>
#include <winrt/Windows.Devices.Bluetooth.Advertisement.h>
#include <winrt/Windows.Storage.Streams.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace winrt;
using namespace winrt::Windows::Devices::WiFiDirect;
using namespace winrt::Windows::Devices::Bluetooth::Advertisement;
using namespace winrt::Windows::Storage::Streams;

namespace {

// Apartment MTA một lần mỗi thread — object MTA gọi tự do chéo thread.
thread_local bool g_apartment_ready = false;

CybervShimStatus ensure_apartment() {
    if (!g_apartment_ready) {
        try {
            winrt::init_apartment(winrt::apartment_type::multi_threaded);
        } catch (hresult_error const&) {
            return CYBERV_SHIM_E_OS_ERROR;
        } catch (...) {
            return CYBERV_SHIM_E_OS_ERROR;
        }
        g_apartment_ready = true;
    }
    return CYBERV_SHIM_OK;
}

// ---- Registry handle → object (handle không tái sử dụng; đếm tăng) --------
uint64_t g_next_handle = 1;
std::mutex g_registry_mutex;

template <typename T>
struct Registry {
    std::unordered_map<uint64_t, std::shared_ptr<T>> map;

    void insert(uint64_t handle, std::shared_ptr<T> obj) {
        std::lock_guard<std::mutex> lock(g_registry_mutex);
        map.emplace(handle, std::move(obj));
    }

    std::shared_ptr<T> take(uint64_t handle) {
        std::lock_guard<std::mutex> lock(g_registry_mutex);
        auto it = map.find(handle);
        if (it == map.end()) {
            return nullptr;
        }
        auto obj = it->second;
        map.erase(it);
        return obj;
    }

    std::shared_ptr<T> get(uint64_t handle) {
        std::lock_guard<std::mutex> lock(g_registry_mutex);
        auto it = map.find(handle);
        return it == map.end() ? nullptr : it->second;
    }
};

Registry<struct WfdPublisherState> g_wfd_publishers;
Registry<BluetoothLEAdvertisementPublisher> g_ble_publishers;
Registry<struct BleWatchState> g_ble_watchers;

// Buffer hàng đợi bounded — drop-cũ-nhất + đếm (số drop đọc được qua API).
constexpr uint32_t QUEUE_CAP = 64;

struct PeerItem {
    uint8_t addr6[6] = {};
    std::wstring device_id;
};

struct WfdPublisherState {
    WiFiDirectAdvertisementPublisher publisher{nullptr};
    // ConnectionRequested nằm trên WiFiDirectConnectionListener (mô hình API
    // trong metadata của SDK này) — listener độc lập với publisher.
    WiFiDirectConnectionListener listener{nullptr};
    WiFiDirectConnectionListener::ConnectionRequested_revoker requested_revoker;
    std::mutex mutex;
    std::deque<std::wstring> requests;
    uint64_t dropped = 0;
};

struct BleWatchState {
    BluetoothLEAdvertisementWatcher watcher{nullptr};
    BluetoothLEAdvertisementWatcher::Received_revoker received_revoker;
    std::mutex mutex;
    std::deque<std::pair<PeerItem, std::vector<uint8_t>>> items;
    uint64_t dropped = 0;
};

// MAC 6 byte từ BluetoothAddress (u64 — 6 byte thấp đáng kể).
void addr_from_u64(uint64_t addr, uint8_t out[6]) {
    for (int i = 0; i < 6; ++i) {
        out[i] = static_cast<uint8_t>((addr >> (8 * (5 - i))) & 0xFF);
    }
}

} // namespace

// ============================ WiFi Direct (M-3) =============================

int cyberv_wfd_advertise_start(uint64_t* handle_out, uint32_t* os_error_out) {
    if (handle_out == nullptr || os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    auto ap = ensure_apartment();
    if (ap != CYBERV_SHIM_OK) {
        return ap;
    }
    try {
        auto state = std::make_shared<WfdPublisherState>();
        state->publisher = WiFiDirectAdvertisementPublisher();
        state->publisher.Advertisement().ListenStateDiscoverability(
            WiFiDirectAdvertisementListenStateDiscoverability::Normal);
        // ConnectionRequested nằm trên WiFiDirectConnectionListener (mô hình
        // API trong metadata của SDK này) — listener độc lập với publisher.
        state->listener = WiFiDirectConnectionListener();
        state->requested_revoker = state->listener.ConnectionRequested(
            winrt::auto_revoke,
            [state](WiFiDirectConnectionListener const&,
                    WiFiDirectConnectionRequestedEventArgs const& args) {
                try {
                    // DeviceInformation ở đây là Devices.Enumeration.DeviceInformation
                    // (type CÓ trong metadata) — Id là chuỗi ổn định do Windows cấp.
                    auto id = args.GetConnectionRequest().DeviceInformation().Id();
                    std::lock_guard<std::mutex> lock(state->mutex);
                    if (state->requests.size() >= QUEUE_CAP) {
                        state->requests.pop_front();
                        state->dropped += 1;
                    }
                    state->requests.push_back(std::wstring(id.c_str()));
                } catch (...) {
                    // Lỗi nguồn sự kiện — bỏ, không lan qua biên giới.
                }
            });
        state->publisher.Start();
        if (state->publisher.Status() == WiFiDirectAdvertisementPublisherStatus::Aborted) {
            // Adapter không hỗ trợ WFD / radio tắt — trung thực.
            *os_error_out = static_cast<uint32_t>(0x80070490); // ERROR_NOT_FOUND
            return CYBERV_SHIM_E_RADIO_OFF;
        }
        uint64_t handle;
        {
            std::lock_guard<std::mutex> lock(g_registry_mutex);
            handle = g_next_handle++;
        }
        g_wfd_publishers.insert(handle, state);
        *handle_out = handle;
        return CYBERV_SHIM_OK;
    } catch (hresult_error const& e) {
        *os_error_out = static_cast<uint32_t>(e.code());
        return CYBERV_SHIM_E_OS_ERROR;
    } catch (...) {
        return CYBERV_SHIM_E_OS_ERROR;
    }
}

int cyberv_wfd_advertise_stop(uint64_t handle, uint32_t* os_error_out) {
    if (os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    auto state = g_wfd_publishers.take(handle);
    if (state == nullptr) {
        return CYBERV_SHIM_E_NOT_INITIALIZED;
    }
    try {
        state->publisher.Stop();
        return CYBERV_SHIM_OK;
    } catch (hresult_error const& e) {
        *os_error_out = static_cast<uint32_t>(e.code());
        return CYBERV_SHIM_E_OS_ERROR;
    } catch (...) {
        return CYBERV_SHIM_E_OS_ERROR;
    }
}

int cyberv_wfd_requests_next(uint64_t handle,
                             uint16_t* device_id_out, uint32_t device_id_cap_wchars,
                             uint32_t* device_id_len_out, uint32_t* os_error_out) {
    if (device_id_out == nullptr || device_id_len_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    *device_id_len_out = 0;
    auto state = g_wfd_publishers.get(handle);
    if (state == nullptr) {
        return CYBERV_SHIM_E_NOT_INITIALIZED;
    }
    std::wstring id;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->requests.empty()) {
            return CYBERV_SHIM_E_NOT_FOUND;
        }
        id = std::move(state->requests.front());
        state->requests.pop_front();
    }
    // Bounds: cắt đúng cap — Rust nhận độ dài thật để biết bị cắt.
    uint32_t copy_len = static_cast<uint32_t>(std::min<size_t>(id.size(), device_id_cap_wchars));
    std::memcpy(device_id_out, id.data(), copy_len * sizeof(wchar_t));
    *device_id_len_out = copy_len;
    return CYBERV_SHIM_OK;
}

int cyberv_wfd_requests_dropped(uint64_t handle, uint64_t* dropped_out) {
    if (dropped_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    auto state = g_wfd_publishers.get(handle);
    if (state == nullptr) {
        return CYBERV_SHIM_E_NOT_INITIALIZED;
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    *dropped_out = state->dropped;
    return CYBERV_SHIM_OK;
}

int cyberv_wfd_connect(const uint16_t* device_id_utf16, uint32_t device_id_len_wchars,
                       uint32_t timeout_ms,
                       uint8_t* remote_ip_out, uint16_t* remote_port_out,
                       uint32_t* os_error_out) {
    if (device_id_utf16 == nullptr || device_id_len_wchars == 0 ||
        remote_ip_out == nullptr || remote_port_out == nullptr || os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    auto ap = ensure_apartment();
    if (ap != CYBERV_SHIM_OK) {
        return ap;
    }
    try {
        hstring id(reinterpret_cast<const wchar_t*>(device_id_utf16),
                   static_cast<uint32_t>(device_id_len_wchars));
        WiFiDirectConnectionParameters params;
        params.GroupOwnerIntent(14); // muốn làm GO — transliteration mặc định
        auto op = WiFiDirectDevice::FromIdAsync(id, params);
        auto status = op.wait_for(std::chrono::milliseconds(timeout_ms));
        if (status == winrt::Windows::Foundation::AsyncStatus::Started) {
            op.Cancel();
            return CYBERV_SHIM_E_TIMEOUT;
        }
        if (status != winrt::Windows::Foundation::AsyncStatus::Completed) {
            return CYBERV_SHIM_E_NOT_FOUND;
        }
        auto device = op.GetResults();
        if (device.ConnectionStatus() != WiFiDirectConnectionStatus::Connected) {
            return CYBERV_SHIM_E_NOT_FOUND;
        }
        auto pairs = device.GetConnectionEndpointPairs();
        if (pairs.Size() == 0) {
            return CYBERV_SHIM_E_NOT_FOUND;
        }
        auto pair = pairs.GetAt(0);
        auto host = pair.RemoteHostName();
        auto port = pair.RemoteServiceName();
        if (port.empty()) {
            return CYBERV_SHIM_E_NOT_FOUND;
        }
        // Port dạng chuỗi số — parse cẩn thận, fail → lỗi rõ.
        int parsed = 0;
        try {
            parsed = std::stoi(std::wstring(port));
        } catch (...) {
            return CYBERV_SHIM_E_OS_ERROR;
        }
        if (parsed <= 0 || parsed > 65535) {
            return CYBERV_SHIM_E_OS_ERROR;
        }
        // IP: IPv4 (điển hình WFD GO) ghi family marker + 4 octet; IPv6 ghi
        // đủ 8 nhóm. Family marker khớp encoding của transport::subnet_scope().
        std::memset(remote_ip_out, 0, 17);
        if (host.Type() == winrt::Windows::Networking::HostNameType::Ipv4) {
            auto canonical = host.CanonicalName();
            unsigned a = 0, b = 0, c = 0, d = 0;
            if (swscanf_s(canonical.c_str(), L"%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
                return CYBERV_SHIM_E_OS_ERROR;
            }
            remote_ip_out[0] = 4;
            remote_ip_out[1] = static_cast<uint8_t>(a);
            remote_ip_out[2] = static_cast<uint8_t>(b);
            remote_ip_out[3] = static_cast<uint8_t>(c);
            remote_ip_out[4] = static_cast<uint8_t>(d);
        } else {
            auto canonical = host.CanonicalName();
            unsigned v[8];
            if (swscanf_s(canonical.c_str(), L"%x:%x:%x:%x:%x:%x:%x:%x",
                          &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) != 8) {
                // IPv6 nén rút gọn — WFD thực tế dùng IPv4 GO; trả lỗi rõ thay
                // vì parse nửa vời.
                return CYBERV_SHIM_E_OS_ERROR;
            }
            remote_ip_out[0] = 6;
            for (int i = 0; i < 8; ++i) {
                remote_ip_out[1 + i * 2] = static_cast<uint8_t>(v[i] >> 8);
                remote_ip_out[2 + i * 2] = static_cast<uint8_t>(v[i] & 0xFF);
            }
        }
        *remote_port_out = static_cast<uint16_t>(parsed);
        return CYBERV_SHIM_OK;
    } catch (hresult_error const& e) {
        *os_error_out = static_cast<uint32_t>(e.code());
        return CYBERV_SHIM_E_OS_ERROR;
    } catch (...) {
        return CYBERV_SHIM_E_OS_ERROR;
    }
}

// ======================= BLE advertisement (M-4) ============================

// Company ID 0xFFFF — Bluetooth SIG dành cho internal/test; sản phẩm thật cần
// ID đăng ký (ghi rõ ở Phụ lục B + docs).
constexpr uint16_t BLE_COMPANY_ID = 0xFFFF;
constexpr uint32_t BLE_PAYLOAD_MAX = 26; // BLE legacy adv data ~26 byte hữu ích

int cyberv_ble_adv_start(const uint8_t* payload, uint32_t len,
                         uint64_t* handle_out, uint32_t* os_error_out) {
    if (payload == nullptr || handle_out == nullptr || os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    if (len == 0 || len > BLE_PAYLOAD_MAX) {
        return CYBERV_SHIM_E_INVALID_ARG; // bounds trước khi đụng radio
    }
    *os_error_out = 0;
    auto ap = ensure_apartment();
    if (ap != CYBERV_SHIM_OK) {
        return ap;
    }
    try {
        auto writer = DataWriter();
        writer.WriteByte(static_cast<uint8_t>(len & 0xFF));
        writer.WriteBytes(winrt::array_view<const uint8_t>(payload, payload + len));
        auto section = BluetoothLEManufacturerData();
        section.CompanyId(BLE_COMPANY_ID);
        section.Data(writer.DetachBuffer());
        auto advertisement = BluetoothLEAdvertisement();
        advertisement.ManufacturerData().Append(section);

        auto publisher = BluetoothLEAdvertisementPublisher(advertisement);
        publisher.Start();
        if (publisher.Status() == BluetoothLEAdvertisementPublisherStatus::Aborted) {
            *os_error_out = static_cast<uint32_t>(0x80070490);
            return CYBERV_SHIM_E_RADIO_OFF;
        }
        auto stored = std::make_shared<BluetoothLEAdvertisementPublisher>(publisher);
        uint64_t handle;
        {
            std::lock_guard<std::mutex> lock(g_registry_mutex);
            handle = g_next_handle++;
        }
        g_ble_publishers.insert(handle, stored);
        *handle_out = handle;
        return CYBERV_SHIM_OK;
    } catch (hresult_error const& e) {
        *os_error_out = static_cast<uint32_t>(e.code());
        return CYBERV_SHIM_E_OS_ERROR;
    } catch (...) {
        return CYBERV_SHIM_E_OS_ERROR;
    }
}

int cyberv_ble_adv_stop(uint64_t handle, uint32_t* os_error_out) {
    if (os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    auto publisher = g_ble_publishers.take(handle);
    if (publisher == nullptr) {
        return CYBERV_SHIM_E_NOT_INITIALIZED;
    }
    try {
        publisher->Stop();
        return CYBERV_SHIM_OK;
    } catch (hresult_error const& e) {
        *os_error_out = static_cast<uint32_t>(e.code());
        return CYBERV_SHIM_E_OS_ERROR;
    } catch (...) {
        return CYBERV_SHIM_E_OS_ERROR;
    }
}

int cyberv_ble_watch_start(uint64_t* handle_out, uint32_t* os_error_out) {
    if (handle_out == nullptr || os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    auto ap = ensure_apartment();
    if (ap != CYBERV_SHIM_OK) {
        return ap;
    }
    try {
        auto state = std::make_shared<BleWatchState>();
        state->watcher = BluetoothLEAdvertisementWatcher();
        state->watcher.ScanningMode(BluetoothLEScanningMode::Active);
        // Filter theo company id — payload dài nào của CyberV cũng nhận.
        auto filter_section = BluetoothLEManufacturerData();
        filter_section.CompanyId(BLE_COMPANY_ID);
        auto filter_adv = BluetoothLEAdvertisement();
        filter_adv.ManufacturerData().Append(filter_section);
        auto filter = BluetoothLEAdvertisementFilter();
        filter.Advertisement(filter_adv);
        state->watcher.AdvertisementFilter(filter);
        state->received_revoker = state->watcher.Received(
            winrt::auto_revoke,
            [state](BluetoothLEAdvertisementWatcher const&,
                    BluetoothLEAdvertisementReceivedEventArgs const& args) {
                try {
                    PeerItem item;
                    addr_from_u64(args.BluetoothAddress(), item.addr6);
                    std::vector<uint8_t> payload;
                    auto adv = args.Advertisement();
                    for (auto const& md : adv.ManufacturerData()) {
                        if (md.CompanyId() != BLE_COMPANY_ID) {
                            continue;
                        }
                        auto data = md.Data();
                        if (data.Length() < 2 || data.Length() > BLE_PAYLOAD_MAX + 1) {
                            continue;
                        }
                        auto reader = DataReader::FromBuffer(data);
                        std::vector<uint8_t> bytes(data.Length());
                        reader.ReadBytes(
                            winrt::array_view<uint8_t>(bytes.data(), bytes.data() + bytes.size()));
                        // Byte 0 là len tự khai — chỉ nhận khi khớp phần còn lại.
                        if (static_cast<uint8_t>(bytes.size() - 1) != bytes[0]) {
                            continue;
                        }
                        payload.assign(bytes.begin() + 1, bytes.end());
                        break;
                    }
                    if (payload.empty()) {
                        return;
                    }
                    std::lock_guard<std::mutex> lock(state->mutex);
                    if (state->items.size() >= QUEUE_CAP) {
                        state->items.pop_front();
                        state->dropped += 1;
                    }
                    state->items.emplace_back(std::move(item), std::move(payload));
                } catch (...) {
                    // Lỗi nguồn sự kiện — bỏ, không lan qua biên giới.
                }
            });
        state->watcher.Start();
        uint64_t handle;
        {
            std::lock_guard<std::mutex> lock(g_registry_mutex);
            handle = g_next_handle++;
        }
        g_ble_watchers.insert(handle, state);
        *handle_out = handle;
        return CYBERV_SHIM_OK;
    } catch (hresult_error const& e) {
        *os_error_out = static_cast<uint32_t>(e.code());
        return CYBERV_SHIM_E_OS_ERROR;
    } catch (...) {
        return CYBERV_SHIM_E_OS_ERROR;
    }
}

int cyberv_ble_watch_stop(uint64_t handle, uint32_t* os_error_out) {
    if (os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    auto state = g_ble_watchers.take(handle);
    if (state == nullptr) {
        return CYBERV_SHIM_E_NOT_INITIALIZED;
    }
    try {
        state->watcher.Stop();
        return CYBERV_SHIM_OK;
    } catch (hresult_error const& e) {
        *os_error_out = static_cast<uint32_t>(e.code());
        return CYBERV_SHIM_E_OS_ERROR;
    } catch (...) {
        return CYBERV_SHIM_E_OS_ERROR;
    }
}

int cyberv_ble_watch_next(uint64_t handle, uint8_t* addr6_out,
                          uint8_t* payload_out, uint32_t payload_cap,
                          uint32_t* payload_len_out, uint32_t* os_error_out) {
    if (addr6_out == nullptr || payload_out == nullptr || payload_len_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    *payload_len_out = 0;
    auto state = g_ble_watchers.get(handle);
    if (state == nullptr) {
        return CYBERV_SHIM_E_NOT_INITIALIZED;
    }
    PeerItem item;
    std::vector<uint8_t> payload;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->items.empty()) {
            return CYBERV_SHIM_E_NOT_FOUND;
        }
        item = state->items.front().first;
        payload = state->items.front().second;
        state->items.pop_front();
    }
    std::memcpy(addr6_out, item.addr6, 6);
    uint32_t copy_len = static_cast<uint32_t>(std::min<size_t>(payload.size(), payload_cap));
    std::memcpy(payload_out, payload.data(), copy_len);
    *payload_len_out = copy_len;
    return CYBERV_SHIM_OK;
}
