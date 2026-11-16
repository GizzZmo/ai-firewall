// MinGW-w64 sine fwpmu.h/fwpmtypes.h mangler en del WFP-konstanter som Windows SDK har.
// Med MSVC + Windows SDK brukes SDK-ens definisjoner og denne filen gjør ingenting.
// Verdiene er identiske med Windows SDK (fwpmu.h / fwpmk.h).
#pragma once
#if defined(_WIN32) && defined(__MINGW32__)

#include <guiddef.h>

#ifndef FWPM_FILTER_FLAG_PERSISTENT
#define FWPM_FILTER_FLAG_PERSISTENT (0x00000001)
#endif
#ifndef FWPM_PROVIDER_FLAG_PERSISTENT
#define FWPM_PROVIDER_FLAG_PERSISTENT (0x00000001)
#endif
#ifndef FWPM_SUBLAYER_FLAG_PERSISTENT
#define FWPM_SUBLAYER_FLAG_PERSISTENT (0x00000001)
#endif

namespace aifw::wfpcompat {
// c38d57d1-05a7-4c33-904f-7fbceee60e82
inline constexpr GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4 = {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
// 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
inline constexpr GUID FWPM_LAYER_ALE_AUTH_CONNECT_V6 = {0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}};
// e1cd9fe7-f4b5-4273-96c0-592e487b8650
inline constexpr GUID FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = {0xe1cd9fe7, 0xf4b5, 0x4273, {0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}};
// a3b42c97-9f04-4672-b87e-cee9c483257f
inline constexpr GUID FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = {0xa3b42c97, 0x9f04, 0x4672, {0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}};
// 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7
inline constexpr GUID FWPM_CONDITION_IP_PROTOCOL = {0x3971ef2b, 0x623e, 0x4f9a, {0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}};
// b235ae9a-1d64-49b8-a44c-5ff3d9095045
inline constexpr GUID FWPM_CONDITION_IP_REMOTE_ADDRESS = {0xb235ae9a, 0x1d64, 0x49b8, {0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}};
// c35a604d-d22b-4e1a-91b4-68f674ee674b
inline constexpr GUID FWPM_CONDITION_IP_REMOTE_PORT = {0xc35a604d, 0xd22b, 0x4e1a, {0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}};
// 0c1ba1af-5765-453f-af22-a8f791ac775b
inline constexpr GUID FWPM_CONDITION_IP_LOCAL_PORT = {0x0c1ba1af, 0x5765, 0x453f, {0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}};
// d78e1e87-8644-4ea5-9437-d809ecefc971
inline constexpr GUID FWPM_CONDITION_ALE_APP_ID = {0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
}  // namespace aifw::wfpcompat

using namespace aifw::wfpcompat;  // NOLINT – gjør navnene tilgjengelige som i SDK

#endif
