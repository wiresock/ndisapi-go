// ndisapi_test.go
//go:generate mockgen -source=ndisapi_interface.go -destination=mock/ndisapi.go

package ndisapi_test

import (
	"testing"
	"unsafe"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"

	"github.com/wiresock/ndisapi-go"
	mock_ndisapi "github.com/wiresock/ndisapi-go/mock"
)

func TestNdisApi_Close(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	mockNdis.EXPECT().Close()

	mockNdis.Close()
}

func TestNdisApi_IsDriverLoaded(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	mockNdis.EXPECT().IsDriverLoaded().Return(true)

	result := mockNdis.IsDriverLoaded()
	assert.True(t, result)
}

func TestNdisApi_DeviceIoControl(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	var data uint32
	ioctlCode := uint32(ndisapi.IOCTL_NDISRD_GET_VERSION)
	dataSize := uint32(unsafe.Sizeof(data))

	mockNdis.EXPECT().DeviceIoControl(
		ioctlCode,
		gomock.Any(),
		dataSize,
		gomock.Any(),
		dataSize,
		nil,
		nil,
	).Return(nil)

	err := mockNdis.DeviceIoControl(
		ioctlCode,
		unsafe.Pointer(&data),
		dataSize,
		unsafe.Pointer(&data),
		dataSize,
		nil,
		nil,
	)
	assert.NoError(t, err)
}

func TestNdisApi_GetVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	expectedVersion := uint32(1234)
	mockNdis.EXPECT().GetVersion().Return(expectedVersion, nil)

	version, err := mockNdis.GetVersion()
	assert.NoError(t, err)
	assert.Equal(t, expectedVersion, version)
}

func TestNdisApi_GetIntermediateBufferPoolSize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	size := uint32(1024)
	mockNdis.EXPECT().GetIntermediateBufferPoolSize(size).Return(nil)

	err := mockNdis.GetIntermediateBufferPoolSize(size)
	assert.NoError(t, err)
}

func TestNdisApi_GetTcpipBoundAdaptersInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	expectedList := &ndisapi.TcpAdapterList{}
	mockNdis.EXPECT().GetTcpipBoundAdaptersInfo().Return(expectedList, nil)

	list, err := mockNdis.GetTcpipBoundAdaptersInfo()
	assert.NoError(t, err)
	assert.Equal(t, expectedList, list)
}

func TestNdisApi_SetAdapterMode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	mode := &ndisapi.AdapterMode{}
	mockNdis.EXPECT().SetAdapterMode(mode).Return(nil)

	err := mockNdis.SetAdapterMode(mode)
	assert.NoError(t, err)
}

func TestNdisApi_GetAdapterMode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	mode := &ndisapi.AdapterMode{}
	mockNdis.EXPECT().GetAdapterMode(mode).Return(nil)

	err := mockNdis.GetAdapterMode(mode)
	assert.NoError(t, err)
}

func TestNdisApi_FlushAdapterPacketQueue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	adapter := ndisapi.Handle{}
	mockNdis.EXPECT().FlushAdapterPacketQueue(adapter).Return(nil)

	err := mockNdis.FlushAdapterPacketQueue(adapter)
	assert.NoError(t, err)
}

func TestNdisApi_GetAdapterPacketQueueSize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	adapter := ndisapi.Handle{}
	var size uint32
	mockNdis.EXPECT().GetAdapterPacketQueueSize(adapter, &size).Return(nil)

	err := mockNdis.GetAdapterPacketQueueSize(adapter, &size)
	assert.NoError(t, err)
}

func TestNdisApi_SetPacketEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	adapter := ndisapi.Handle{}
	event := windows.Handle(1234)
	mockNdis.EXPECT().SetPacketEvent(adapter, event).Return(nil)

	err := mockNdis.SetPacketEvent(adapter, event)
	assert.NoError(t, err)
}

func TestNdisApi_ConvertWindows2000AdapterName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	adapterName := "testAdapter"
	expectedName := "userFriendlyName"
	mockNdis.EXPECT().ConvertWindows2000AdapterName(adapterName).Return(expectedName)

	name := mockNdis.ConvertWindows2000AdapterName(adapterName)
	assert.Equal(t, expectedName, name)
}

func TestNdisApi_InitializeFastIo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	fastIo := &ndisapi.InitializeFastIOSection{}
	size := uint32(unsafe.Sizeof(*fastIo))

	mockNdis.EXPECT().InitializeFastIo(fastIo, size).Return(true)

	result := mockNdis.InitializeFastIo(fastIo, size)
	assert.True(t, result)
}

func TestNdisApi_AddSecondaryFastIo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	fastIo := &ndisapi.InitializeFastIOSection{}
	size := uint32(unsafe.Sizeof(*fastIo))

	mockNdis.EXPECT().AddSecondaryFastIo(fastIo, size).Return(true)

	result := mockNdis.AddSecondaryFastIo(fastIo, size)
	assert.True(t, result)
}

func TestNdisApi_ReadPacketsUnsorted(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packets := make([]*ndisapi.IntermediateBuffer, 10)
	var packetsSuccess uint32

	mockNdis.EXPECT().ReadPacketsUnsorted(packets, uint32(len(packets)), &packetsSuccess).Return(true)

	result := mockNdis.ReadPacketsUnsorted(packets, uint32(len(packets)), &packetsSuccess)
	assert.True(t, result)
}

func TestNdisApi_SendPacketsToAdaptersUnsorted(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packets := make([]*ndisapi.IntermediateBuffer, 10)
	var packetsSuccess uint32

	mockNdis.EXPECT().SendPacketsToAdaptersUnsorted(packets, uint32(len(packets)), &packetsSuccess).Return(true)

	result := mockNdis.SendPacketsToAdaptersUnsorted(packets, uint32(len(packets)), &packetsSuccess)
	assert.True(t, result)
}

func TestNdisApi_SendPacketsToMstcpUnsorted(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packets := make([]*ndisapi.IntermediateBuffer, 10)
	var packetsSuccess uint32

	mockNdis.EXPECT().SendPacketsToMstcpUnsorted(packets, uint32(len(packets)), &packetsSuccess).Return(true)

	result := mockNdis.SendPacketsToMstcpUnsorted(packets, uint32(len(packets)), &packetsSuccess)
	assert.True(t, result)
}

func TestNdisApi_SendPacketToMstcp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packet := &ndisapi.EtherRequest{}
	mockNdis.EXPECT().SendPacketToMstcp(packet).Return(nil)

	err := mockNdis.SendPacketToMstcp(packet)
	assert.NoError(t, err)
}

func TestNdisApi_SendPacketToAdapter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packet := &ndisapi.EtherRequest{}
	mockNdis.EXPECT().SendPacketToAdapter(packet).Return(nil)

	err := mockNdis.SendPacketToAdapter(packet)
	assert.NoError(t, err)
}

func TestNdisApi_ReadPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packet := &ndisapi.EtherRequest{}
	mockNdis.EXPECT().ReadPacket(packet).Return(true)

	result := mockNdis.ReadPacket(packet)
	assert.True(t, result)
}

func TestNdisApi_SendPacketsToMstcp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packet := &ndisapi.EtherMultiRequest{}
	mockNdis.EXPECT().SendPacketsToMstcp(packet).Return(nil)

	err := mockNdis.SendPacketsToMstcp(packet)
	assert.NoError(t, err)
}

func TestNdisApi_SendPacketsToAdapter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packet := &ndisapi.EtherMultiRequest{}
	mockNdis.EXPECT().SendPacketsToAdapter(packet).Return(nil)

	err := mockNdis.SendPacketsToAdapter(packet)
	assert.NoError(t, err)
}

func TestNdisApi_ReadPackets(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packet := &ndisapi.EtherMultiRequest{}
	mockNdis.EXPECT().ReadPackets(packet).Return(true)

	result := mockNdis.ReadPackets(packet)
	assert.True(t, result)
}

func TestNdisApi_SetPacketFilterTable(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	packet := &ndisapi.StaticFilterTable{}
	mockNdis.EXPECT().SetPacketFilterTable(packet).Return(nil)

	err := mockNdis.SetPacketFilterTable(packet)
	assert.NoError(t, err)
}

func TestNdisApi_AddStaticFilterFront(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	filter := &ndisapi.StaticFilter{}
	mockNdis.EXPECT().AddStaticFilterFront(filter).Return(nil)

	err := mockNdis.AddStaticFilterFront(filter)
	assert.NoError(t, err)
}

func TestNdisApi_AddStaticFilterBack(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	filter := &ndisapi.StaticFilter{}
	mockNdis.EXPECT().AddStaticFilterBack(filter).Return(nil)

	err := mockNdis.AddStaticFilterBack(filter)
	assert.NoError(t, err)
}

func TestNdisApi_InsertStaticFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	filter := &ndisapi.StaticFilter{}
	position := uint32(1)
	mockNdis.EXPECT().InsertStaticFilter(filter, position).Return(nil)

	err := mockNdis.InsertStaticFilter(filter, position)
	assert.NoError(t, err)
}

func TestNdisApi_RemoveStaticFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	filterID := uint32(1)
	mockNdis.EXPECT().RemoveStaticFilter(filterID).Return(nil)

	err := mockNdis.RemoveStaticFilter(filterID)
	assert.NoError(t, err)
}

func TestNdisApi_ResetPacketFilterTable(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	mockNdis.EXPECT().ResetPacketFilterTable().Return(nil)

	err := mockNdis.ResetPacketFilterTable()
	assert.NoError(t, err)
}

func TestNdisApi_GetPacketFilterTableSize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	expectedSize := uint32(10)
	mockNdis.EXPECT().GetPacketFilterTableSize().Return(&expectedSize, nil)

	size, err := mockNdis.GetPacketFilterTableSize()
	assert.NoError(t, err)
	assert.Equal(t, expectedSize, *size)
}

func TestNdisApi_GetPacketFilterTable(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	expectedTable := &ndisapi.StaticFilterTable{}
	mockNdis.EXPECT().GetPacketFilterTable().Return(expectedTable, nil)

	table, err := mockNdis.GetPacketFilterTable()
	assert.NoError(t, err)
	assert.Equal(t, expectedTable, table)
}

func TestNdisApi_GetPacketFilterTableResetStats(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	expectedTable := &ndisapi.StaticFilterTable{}
	mockNdis.EXPECT().GetPacketFilterTableResetStats().Return(expectedTable, nil)

	table, err := mockNdis.GetPacketFilterTableResetStats()
	assert.NoError(t, err)
	assert.Equal(t, expectedTable, table)
}

func TestNdisApi_SetPacketFilterCacheState(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	state := true
	mockNdis.EXPECT().SetPacketFilterCacheState(state).Return(nil)

	err := mockNdis.SetPacketFilterCacheState(state)
	assert.NoError(t, err)
}

func TestNdisApi_SetPacketFragmentCacheState(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	state := true
	mockNdis.EXPECT().SetPacketFragmentCacheState(state).Return(nil)

	err := mockNdis.SetPacketFragmentCacheState(state)
	assert.NoError(t, err)
}

// func TestNdisApi_IsNdiswanInterfaces(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
// 	adapterName := "testAdapter"
// 	ndiswanName := "NDISWAN"

// 	mockNdis.EXPECT().IsNdiswanInterfaces(adapterName, ndiswanName).Return(true)

// 	result := mockNdis.IsNdiswanInterfaces(adapterName, ndiswanName)
// 	assert.True(t, result)
// }

func TestNdisApi_IsNdiswanIP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	adapterName := "testAdapter"

	mockNdis.EXPECT().IsNdiswanIP(adapterName).Return(true)

	result := mockNdis.IsNdiswanIP(adapterName)
	assert.True(t, result)
}

func TestNdisApi_IsNdiswanIPv6(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	adapterName := "testAdapter"

	mockNdis.EXPECT().IsNdiswanIPv6(adapterName).Return(true)

	result := mockNdis.IsNdiswanIPv6(adapterName)
	assert.True(t, result)
}

func TestNdisApi_IsNdiswanBh(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)
	adapterName := "testAdapter"

	mockNdis.EXPECT().IsNdiswanBh(adapterName).Return(true)

	result := mockNdis.IsNdiswanBh(adapterName)
	assert.True(t, result)
}

func TestNdisApi_IsWindows10OrGreater(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNdis := mock_ndisapi.NewMockNdisApiInterface(ctrl)

	mockNdis.EXPECT().IsWindows10OrGreater().Return(true)

	result := mockNdis.IsWindows10OrGreater()
	assert.True(t, result)
}