//go:build windows

package ndisapi

// IOCTL Codes For NDIS Packet redirect Driver
const (
	FILE_DEVICE_NDISRD = 0x00008300
	NDISRD_IOCTL_INDEX = 0x830

	// from winioctl.h
	METHOD_BUFFERED = 0
	FILE_ANY_ACCESS = 0

	IOCTL_NDISRD_GET_VERSION                     = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | (NDISRD_IOCTL_INDEX << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_TCPIP_INTERFACES            = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 1) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER          = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 2) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKET_TO_MSTCP            = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 3) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_READ_PACKET                     = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 4) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_ADAPTER_MODE                = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 5) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE             = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 6) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_EVENT                       = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 7) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_NDIS_SET_REQUEST                = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 8) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_NDIS_GET_REQUEST                = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 9) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_WAN_EVENT                   = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 10) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_ADAPTER_EVENT               = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 11) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_ADAPTER_QUEUE_SIZE              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 12) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_ADAPTER_MODE                = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 13) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_PACKET_FILTERS              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 14) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_RESET_PACKET_FILTERS            = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 15) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE    = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 16) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_PACKET_FILTERS              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 17) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS  = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 18) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_RAS_LINKS                   = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 19) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER         = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 20) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP           = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 21) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_READ_PACKETS                    = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 22) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT      = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 23) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_INITIALIZE_FAST_IO              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 24) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_READ_PACKETS_UNSORTED           = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 25) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 26) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED   = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 27) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION      = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 28) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_QUERY_IB_POOL_SIZE              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 29) << 2) | METHOD_BUFFERED
)
