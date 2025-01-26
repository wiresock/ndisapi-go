package driver

const MaximumBlockNum = 10

type FilterState uint32

const (
	FilterStateStopped FilterState = iota
	FilterStateStarting
	FilterStateRunning
	FilterStateStopping
)

type PacketDirection int

const (
	PacketDirectionIn PacketDirection = iota
	PacketDirectionOut
	PacketDirectionBoth
)

type PacketFilter interface {
	StartFilter(adapterIdx int) error
	Close() error
	Reconfigure() error
	GetFilterState() FilterState
}
