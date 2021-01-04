#include <string.h>
namespace LDK {
class Event {
private:
	LDKEvent self;
public:
	Event(const Event&) = delete;
	Event(Event&& o) : self(o.self) { memset(&o, 0, sizeof(Event)); }
	Event(LDKEvent&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKEvent)); }
	operator LDKEvent() && { LDKEvent res = self; memset(&self, 0, sizeof(LDKEvent)); return res; }
	~Event() { Event_free(self); }
	Event& operator=(Event&& o) { Event_free(self); self = o.self; memset(&o, 0, sizeof(Event)); return *this; }
	LDKEvent* operator &() { return &self; }
	LDKEvent* operator ->() { return &self; }
	const LDKEvent* operator &() const { return &self; }
	const LDKEvent* operator ->() const { return &self; }
};
class MessageSendEvent {
private:
	LDKMessageSendEvent self;
public:
	MessageSendEvent(const MessageSendEvent&) = delete;
	MessageSendEvent(MessageSendEvent&& o) : self(o.self) { memset(&o, 0, sizeof(MessageSendEvent)); }
	MessageSendEvent(LDKMessageSendEvent&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMessageSendEvent)); }
	operator LDKMessageSendEvent() && { LDKMessageSendEvent res = self; memset(&self, 0, sizeof(LDKMessageSendEvent)); return res; }
	~MessageSendEvent() { MessageSendEvent_free(self); }
	MessageSendEvent& operator=(MessageSendEvent&& o) { MessageSendEvent_free(self); self = o.self; memset(&o, 0, sizeof(MessageSendEvent)); return *this; }
	LDKMessageSendEvent* operator &() { return &self; }
	LDKMessageSendEvent* operator ->() { return &self; }
	const LDKMessageSendEvent* operator &() const { return &self; }
	const LDKMessageSendEvent* operator ->() const { return &self; }
};
class MessageSendEventsProvider {
private:
	LDKMessageSendEventsProvider self;
public:
	MessageSendEventsProvider(const MessageSendEventsProvider&) = delete;
	MessageSendEventsProvider(MessageSendEventsProvider&& o) : self(o.self) { memset(&o, 0, sizeof(MessageSendEventsProvider)); }
	MessageSendEventsProvider(LDKMessageSendEventsProvider&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMessageSendEventsProvider)); }
	operator LDKMessageSendEventsProvider() && { LDKMessageSendEventsProvider res = self; memset(&self, 0, sizeof(LDKMessageSendEventsProvider)); return res; }
	~MessageSendEventsProvider() { MessageSendEventsProvider_free(self); }
	MessageSendEventsProvider& operator=(MessageSendEventsProvider&& o) { MessageSendEventsProvider_free(self); self = o.self; memset(&o, 0, sizeof(MessageSendEventsProvider)); return *this; }
	LDKMessageSendEventsProvider* operator &() { return &self; }
	LDKMessageSendEventsProvider* operator ->() { return &self; }
	const LDKMessageSendEventsProvider* operator &() const { return &self; }
	const LDKMessageSendEventsProvider* operator ->() const { return &self; }
};
class EventsProvider {
private:
	LDKEventsProvider self;
public:
	EventsProvider(const EventsProvider&) = delete;
	EventsProvider(EventsProvider&& o) : self(o.self) { memset(&o, 0, sizeof(EventsProvider)); }
	EventsProvider(LDKEventsProvider&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKEventsProvider)); }
	operator LDKEventsProvider() && { LDKEventsProvider res = self; memset(&self, 0, sizeof(LDKEventsProvider)); return res; }
	~EventsProvider() { EventsProvider_free(self); }
	EventsProvider& operator=(EventsProvider&& o) { EventsProvider_free(self); self = o.self; memset(&o, 0, sizeof(EventsProvider)); return *this; }
	LDKEventsProvider* operator &() { return &self; }
	LDKEventsProvider* operator ->() { return &self; }
	const LDKEventsProvider* operator &() const { return &self; }
	const LDKEventsProvider* operator ->() const { return &self; }
};
class APIError {
private:
	LDKAPIError self;
public:
	APIError(const APIError&) = delete;
	APIError(APIError&& o) : self(o.self) { memset(&o, 0, sizeof(APIError)); }
	APIError(LDKAPIError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAPIError)); }
	operator LDKAPIError() && { LDKAPIError res = self; memset(&self, 0, sizeof(LDKAPIError)); return res; }
	~APIError() { APIError_free(self); }
	APIError& operator=(APIError&& o) { APIError_free(self); self = o.self; memset(&o, 0, sizeof(APIError)); return *this; }
	LDKAPIError* operator &() { return &self; }
	LDKAPIError* operator ->() { return &self; }
	const LDKAPIError* operator &() const { return &self; }
	const LDKAPIError* operator ->() const { return &self; }
};
class Level {
private:
	LDKLevel self;
public:
	Level(const Level&) = delete;
	Level(Level&& o) : self(o.self) { memset(&o, 0, sizeof(Level)); }
	Level(LDKLevel&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKLevel)); }
	operator LDKLevel() && { LDKLevel res = self; memset(&self, 0, sizeof(LDKLevel)); return res; }
	Level& operator=(Level&& o) { self = o.self; memset(&o, 0, sizeof(Level)); return *this; }
	LDKLevel* operator &() { return &self; }
	LDKLevel* operator ->() { return &self; }
	const LDKLevel* operator &() const { return &self; }
	const LDKLevel* operator ->() const { return &self; }
};
class Logger {
private:
	LDKLogger self;
public:
	Logger(const Logger&) = delete;
	Logger(Logger&& o) : self(o.self) { memset(&o, 0, sizeof(Logger)); }
	Logger(LDKLogger&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKLogger)); }
	operator LDKLogger() && { LDKLogger res = self; memset(&self, 0, sizeof(LDKLogger)); return res; }
	~Logger() { Logger_free(self); }
	Logger& operator=(Logger&& o) { Logger_free(self); self = o.self; memset(&o, 0, sizeof(Logger)); return *this; }
	LDKLogger* operator &() { return &self; }
	LDKLogger* operator ->() { return &self; }
	const LDKLogger* operator &() const { return &self; }
	const LDKLogger* operator ->() const { return &self; }
};
class ChannelHandshakeConfig {
private:
	LDKChannelHandshakeConfig self;
public:
	ChannelHandshakeConfig(const ChannelHandshakeConfig&) = delete;
	ChannelHandshakeConfig(ChannelHandshakeConfig&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelHandshakeConfig)); }
	ChannelHandshakeConfig(LDKChannelHandshakeConfig&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelHandshakeConfig)); }
	operator LDKChannelHandshakeConfig() && { LDKChannelHandshakeConfig res = self; memset(&self, 0, sizeof(LDKChannelHandshakeConfig)); return res; }
	~ChannelHandshakeConfig() { ChannelHandshakeConfig_free(self); }
	ChannelHandshakeConfig& operator=(ChannelHandshakeConfig&& o) { ChannelHandshakeConfig_free(self); self = o.self; memset(&o, 0, sizeof(ChannelHandshakeConfig)); return *this; }
	LDKChannelHandshakeConfig* operator &() { return &self; }
	LDKChannelHandshakeConfig* operator ->() { return &self; }
	const LDKChannelHandshakeConfig* operator &() const { return &self; }
	const LDKChannelHandshakeConfig* operator ->() const { return &self; }
};
class ChannelHandshakeLimits {
private:
	LDKChannelHandshakeLimits self;
public:
	ChannelHandshakeLimits(const ChannelHandshakeLimits&) = delete;
	ChannelHandshakeLimits(ChannelHandshakeLimits&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelHandshakeLimits)); }
	ChannelHandshakeLimits(LDKChannelHandshakeLimits&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelHandshakeLimits)); }
	operator LDKChannelHandshakeLimits() && { LDKChannelHandshakeLimits res = self; memset(&self, 0, sizeof(LDKChannelHandshakeLimits)); return res; }
	~ChannelHandshakeLimits() { ChannelHandshakeLimits_free(self); }
	ChannelHandshakeLimits& operator=(ChannelHandshakeLimits&& o) { ChannelHandshakeLimits_free(self); self = o.self; memset(&o, 0, sizeof(ChannelHandshakeLimits)); return *this; }
	LDKChannelHandshakeLimits* operator &() { return &self; }
	LDKChannelHandshakeLimits* operator ->() { return &self; }
	const LDKChannelHandshakeLimits* operator &() const { return &self; }
	const LDKChannelHandshakeLimits* operator ->() const { return &self; }
};
class ChannelConfig {
private:
	LDKChannelConfig self;
public:
	ChannelConfig(const ChannelConfig&) = delete;
	ChannelConfig(ChannelConfig&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelConfig)); }
	ChannelConfig(LDKChannelConfig&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelConfig)); }
	operator LDKChannelConfig() && { LDKChannelConfig res = self; memset(&self, 0, sizeof(LDKChannelConfig)); return res; }
	~ChannelConfig() { ChannelConfig_free(self); }
	ChannelConfig& operator=(ChannelConfig&& o) { ChannelConfig_free(self); self = o.self; memset(&o, 0, sizeof(ChannelConfig)); return *this; }
	LDKChannelConfig* operator &() { return &self; }
	LDKChannelConfig* operator ->() { return &self; }
	const LDKChannelConfig* operator &() const { return &self; }
	const LDKChannelConfig* operator ->() const { return &self; }
};
class UserConfig {
private:
	LDKUserConfig self;
public:
	UserConfig(const UserConfig&) = delete;
	UserConfig(UserConfig&& o) : self(o.self) { memset(&o, 0, sizeof(UserConfig)); }
	UserConfig(LDKUserConfig&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUserConfig)); }
	operator LDKUserConfig() && { LDKUserConfig res = self; memset(&self, 0, sizeof(LDKUserConfig)); return res; }
	~UserConfig() { UserConfig_free(self); }
	UserConfig& operator=(UserConfig&& o) { UserConfig_free(self); self = o.self; memset(&o, 0, sizeof(UserConfig)); return *this; }
	LDKUserConfig* operator &() { return &self; }
	LDKUserConfig* operator ->() { return &self; }
	const LDKUserConfig* operator &() const { return &self; }
	const LDKUserConfig* operator ->() const { return &self; }
};
class BroadcasterInterface {
private:
	LDKBroadcasterInterface self;
public:
	BroadcasterInterface(const BroadcasterInterface&) = delete;
	BroadcasterInterface(BroadcasterInterface&& o) : self(o.self) { memset(&o, 0, sizeof(BroadcasterInterface)); }
	BroadcasterInterface(LDKBroadcasterInterface&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBroadcasterInterface)); }
	operator LDKBroadcasterInterface() && { LDKBroadcasterInterface res = self; memset(&self, 0, sizeof(LDKBroadcasterInterface)); return res; }
	~BroadcasterInterface() { BroadcasterInterface_free(self); }
	BroadcasterInterface& operator=(BroadcasterInterface&& o) { BroadcasterInterface_free(self); self = o.self; memset(&o, 0, sizeof(BroadcasterInterface)); return *this; }
	LDKBroadcasterInterface* operator &() { return &self; }
	LDKBroadcasterInterface* operator ->() { return &self; }
	const LDKBroadcasterInterface* operator &() const { return &self; }
	const LDKBroadcasterInterface* operator ->() const { return &self; }
};
class ConfirmationTarget {
private:
	LDKConfirmationTarget self;
public:
	ConfirmationTarget(const ConfirmationTarget&) = delete;
	ConfirmationTarget(ConfirmationTarget&& o) : self(o.self) { memset(&o, 0, sizeof(ConfirmationTarget)); }
	ConfirmationTarget(LDKConfirmationTarget&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKConfirmationTarget)); }
	operator LDKConfirmationTarget() && { LDKConfirmationTarget res = self; memset(&self, 0, sizeof(LDKConfirmationTarget)); return res; }
	ConfirmationTarget& operator=(ConfirmationTarget&& o) { self = o.self; memset(&o, 0, sizeof(ConfirmationTarget)); return *this; }
	LDKConfirmationTarget* operator &() { return &self; }
	LDKConfirmationTarget* operator ->() { return &self; }
	const LDKConfirmationTarget* operator &() const { return &self; }
	const LDKConfirmationTarget* operator ->() const { return &self; }
};
class FeeEstimator {
private:
	LDKFeeEstimator self;
public:
	FeeEstimator(const FeeEstimator&) = delete;
	FeeEstimator(FeeEstimator&& o) : self(o.self) { memset(&o, 0, sizeof(FeeEstimator)); }
	FeeEstimator(LDKFeeEstimator&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFeeEstimator)); }
	operator LDKFeeEstimator() && { LDKFeeEstimator res = self; memset(&self, 0, sizeof(LDKFeeEstimator)); return res; }
	~FeeEstimator() { FeeEstimator_free(self); }
	FeeEstimator& operator=(FeeEstimator&& o) { FeeEstimator_free(self); self = o.self; memset(&o, 0, sizeof(FeeEstimator)); return *this; }
	LDKFeeEstimator* operator &() { return &self; }
	LDKFeeEstimator* operator ->() { return &self; }
	const LDKFeeEstimator* operator &() const { return &self; }
	const LDKFeeEstimator* operator ->() const { return &self; }
};
class ChainMonitor {
private:
	LDKChainMonitor self;
public:
	ChainMonitor(const ChainMonitor&) = delete;
	ChainMonitor(ChainMonitor&& o) : self(o.self) { memset(&o, 0, sizeof(ChainMonitor)); }
	ChainMonitor(LDKChainMonitor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChainMonitor)); }
	operator LDKChainMonitor() && { LDKChainMonitor res = self; memset(&self, 0, sizeof(LDKChainMonitor)); return res; }
	~ChainMonitor() { ChainMonitor_free(self); }
	ChainMonitor& operator=(ChainMonitor&& o) { ChainMonitor_free(self); self = o.self; memset(&o, 0, sizeof(ChainMonitor)); return *this; }
	LDKChainMonitor* operator &() { return &self; }
	LDKChainMonitor* operator ->() { return &self; }
	const LDKChainMonitor* operator &() const { return &self; }
	const LDKChainMonitor* operator ->() const { return &self; }
};
class ChannelMonitorUpdate {
private:
	LDKChannelMonitorUpdate self;
public:
	ChannelMonitorUpdate(const ChannelMonitorUpdate&) = delete;
	ChannelMonitorUpdate(ChannelMonitorUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelMonitorUpdate)); }
	ChannelMonitorUpdate(LDKChannelMonitorUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelMonitorUpdate)); }
	operator LDKChannelMonitorUpdate() && { LDKChannelMonitorUpdate res = self; memset(&self, 0, sizeof(LDKChannelMonitorUpdate)); return res; }
	~ChannelMonitorUpdate() { ChannelMonitorUpdate_free(self); }
	ChannelMonitorUpdate& operator=(ChannelMonitorUpdate&& o) { ChannelMonitorUpdate_free(self); self = o.self; memset(&o, 0, sizeof(ChannelMonitorUpdate)); return *this; }
	LDKChannelMonitorUpdate* operator &() { return &self; }
	LDKChannelMonitorUpdate* operator ->() { return &self; }
	const LDKChannelMonitorUpdate* operator &() const { return &self; }
	const LDKChannelMonitorUpdate* operator ->() const { return &self; }
};
class ChannelMonitorUpdateErr {
private:
	LDKChannelMonitorUpdateErr self;
public:
	ChannelMonitorUpdateErr(const ChannelMonitorUpdateErr&) = delete;
	ChannelMonitorUpdateErr(ChannelMonitorUpdateErr&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelMonitorUpdateErr)); }
	ChannelMonitorUpdateErr(LDKChannelMonitorUpdateErr&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelMonitorUpdateErr)); }
	operator LDKChannelMonitorUpdateErr() && { LDKChannelMonitorUpdateErr res = self; memset(&self, 0, sizeof(LDKChannelMonitorUpdateErr)); return res; }
	ChannelMonitorUpdateErr& operator=(ChannelMonitorUpdateErr&& o) { self = o.self; memset(&o, 0, sizeof(ChannelMonitorUpdateErr)); return *this; }
	LDKChannelMonitorUpdateErr* operator &() { return &self; }
	LDKChannelMonitorUpdateErr* operator ->() { return &self; }
	const LDKChannelMonitorUpdateErr* operator &() const { return &self; }
	const LDKChannelMonitorUpdateErr* operator ->() const { return &self; }
};
class MonitorUpdateError {
private:
	LDKMonitorUpdateError self;
public:
	MonitorUpdateError(const MonitorUpdateError&) = delete;
	MonitorUpdateError(MonitorUpdateError&& o) : self(o.self) { memset(&o, 0, sizeof(MonitorUpdateError)); }
	MonitorUpdateError(LDKMonitorUpdateError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMonitorUpdateError)); }
	operator LDKMonitorUpdateError() && { LDKMonitorUpdateError res = self; memset(&self, 0, sizeof(LDKMonitorUpdateError)); return res; }
	~MonitorUpdateError() { MonitorUpdateError_free(self); }
	MonitorUpdateError& operator=(MonitorUpdateError&& o) { MonitorUpdateError_free(self); self = o.self; memset(&o, 0, sizeof(MonitorUpdateError)); return *this; }
	LDKMonitorUpdateError* operator &() { return &self; }
	LDKMonitorUpdateError* operator ->() { return &self; }
	const LDKMonitorUpdateError* operator &() const { return &self; }
	const LDKMonitorUpdateError* operator ->() const { return &self; }
};
class MonitorEvent {
private:
	LDKMonitorEvent self;
public:
	MonitorEvent(const MonitorEvent&) = delete;
	MonitorEvent(MonitorEvent&& o) : self(o.self) { memset(&o, 0, sizeof(MonitorEvent)); }
	MonitorEvent(LDKMonitorEvent&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMonitorEvent)); }
	operator LDKMonitorEvent() && { LDKMonitorEvent res = self; memset(&self, 0, sizeof(LDKMonitorEvent)); return res; }
	~MonitorEvent() { MonitorEvent_free(self); }
	MonitorEvent& operator=(MonitorEvent&& o) { MonitorEvent_free(self); self = o.self; memset(&o, 0, sizeof(MonitorEvent)); return *this; }
	LDKMonitorEvent* operator &() { return &self; }
	LDKMonitorEvent* operator ->() { return &self; }
	const LDKMonitorEvent* operator &() const { return &self; }
	const LDKMonitorEvent* operator ->() const { return &self; }
};
class HTLCUpdate {
private:
	LDKHTLCUpdate self;
public:
	HTLCUpdate(const HTLCUpdate&) = delete;
	HTLCUpdate(HTLCUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(HTLCUpdate)); }
	HTLCUpdate(LDKHTLCUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKHTLCUpdate)); }
	operator LDKHTLCUpdate() && { LDKHTLCUpdate res = self; memset(&self, 0, sizeof(LDKHTLCUpdate)); return res; }
	~HTLCUpdate() { HTLCUpdate_free(self); }
	HTLCUpdate& operator=(HTLCUpdate&& o) { HTLCUpdate_free(self); self = o.self; memset(&o, 0, sizeof(HTLCUpdate)); return *this; }
	LDKHTLCUpdate* operator &() { return &self; }
	LDKHTLCUpdate* operator ->() { return &self; }
	const LDKHTLCUpdate* operator &() const { return &self; }
	const LDKHTLCUpdate* operator ->() const { return &self; }
};
class ChannelMonitor {
private:
	LDKChannelMonitor self;
public:
	ChannelMonitor(const ChannelMonitor&) = delete;
	ChannelMonitor(ChannelMonitor&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelMonitor)); }
	ChannelMonitor(LDKChannelMonitor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelMonitor)); }
	operator LDKChannelMonitor() && { LDKChannelMonitor res = self; memset(&self, 0, sizeof(LDKChannelMonitor)); return res; }
	~ChannelMonitor() { ChannelMonitor_free(self); }
	ChannelMonitor& operator=(ChannelMonitor&& o) { ChannelMonitor_free(self); self = o.self; memset(&o, 0, sizeof(ChannelMonitor)); return *this; }
	LDKChannelMonitor* operator &() { return &self; }
	LDKChannelMonitor* operator ->() { return &self; }
	const LDKChannelMonitor* operator &() const { return &self; }
	const LDKChannelMonitor* operator ->() const { return &self; }
};
class Persist {
private:
	LDKPersist self;
public:
	Persist(const Persist&) = delete;
	Persist(Persist&& o) : self(o.self) { memset(&o, 0, sizeof(Persist)); }
	Persist(LDKPersist&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPersist)); }
	operator LDKPersist() && { LDKPersist res = self; memset(&self, 0, sizeof(LDKPersist)); return res; }
	~Persist() { Persist_free(self); }
	Persist& operator=(Persist&& o) { Persist_free(self); self = o.self; memset(&o, 0, sizeof(Persist)); return *this; }
	LDKPersist* operator &() { return &self; }
	LDKPersist* operator ->() { return &self; }
	const LDKPersist* operator &() const { return &self; }
	const LDKPersist* operator ->() const { return &self; }
};
class OutPoint {
private:
	LDKOutPoint self;
public:
	OutPoint(const OutPoint&) = delete;
	OutPoint(OutPoint&& o) : self(o.self) { memset(&o, 0, sizeof(OutPoint)); }
	OutPoint(LDKOutPoint&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKOutPoint)); }
	operator LDKOutPoint() && { LDKOutPoint res = self; memset(&self, 0, sizeof(LDKOutPoint)); return res; }
	~OutPoint() { OutPoint_free(self); }
	OutPoint& operator=(OutPoint&& o) { OutPoint_free(self); self = o.self; memset(&o, 0, sizeof(OutPoint)); return *this; }
	LDKOutPoint* operator &() { return &self; }
	LDKOutPoint* operator ->() { return &self; }
	const LDKOutPoint* operator &() const { return &self; }
	const LDKOutPoint* operator ->() const { return &self; }
};
class SpendableOutputDescriptor {
private:
	LDKSpendableOutputDescriptor self;
public:
	SpendableOutputDescriptor(const SpendableOutputDescriptor&) = delete;
	SpendableOutputDescriptor(SpendableOutputDescriptor&& o) : self(o.self) { memset(&o, 0, sizeof(SpendableOutputDescriptor)); }
	SpendableOutputDescriptor(LDKSpendableOutputDescriptor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSpendableOutputDescriptor)); }
	operator LDKSpendableOutputDescriptor() && { LDKSpendableOutputDescriptor res = self; memset(&self, 0, sizeof(LDKSpendableOutputDescriptor)); return res; }
	~SpendableOutputDescriptor() { SpendableOutputDescriptor_free(self); }
	SpendableOutputDescriptor& operator=(SpendableOutputDescriptor&& o) { SpendableOutputDescriptor_free(self); self = o.self; memset(&o, 0, sizeof(SpendableOutputDescriptor)); return *this; }
	LDKSpendableOutputDescriptor* operator &() { return &self; }
	LDKSpendableOutputDescriptor* operator ->() { return &self; }
	const LDKSpendableOutputDescriptor* operator &() const { return &self; }
	const LDKSpendableOutputDescriptor* operator ->() const { return &self; }
};
class ChannelKeys {
private:
	LDKChannelKeys self;
public:
	ChannelKeys(const ChannelKeys&) = delete;
	ChannelKeys(ChannelKeys&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelKeys)); }
	ChannelKeys(LDKChannelKeys&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelKeys)); }
	operator LDKChannelKeys() && { LDKChannelKeys res = self; memset(&self, 0, sizeof(LDKChannelKeys)); return res; }
	~ChannelKeys() { ChannelKeys_free(self); }
	ChannelKeys& operator=(ChannelKeys&& o) { ChannelKeys_free(self); self = o.self; memset(&o, 0, sizeof(ChannelKeys)); return *this; }
	LDKChannelKeys* operator &() { return &self; }
	LDKChannelKeys* operator ->() { return &self; }
	const LDKChannelKeys* operator &() const { return &self; }
	const LDKChannelKeys* operator ->() const { return &self; }
};
class KeysInterface {
private:
	LDKKeysInterface self;
public:
	KeysInterface(const KeysInterface&) = delete;
	KeysInterface(KeysInterface&& o) : self(o.self) { memset(&o, 0, sizeof(KeysInterface)); }
	KeysInterface(LDKKeysInterface&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKKeysInterface)); }
	operator LDKKeysInterface() && { LDKKeysInterface res = self; memset(&self, 0, sizeof(LDKKeysInterface)); return res; }
	~KeysInterface() { KeysInterface_free(self); }
	KeysInterface& operator=(KeysInterface&& o) { KeysInterface_free(self); self = o.self; memset(&o, 0, sizeof(KeysInterface)); return *this; }
	LDKKeysInterface* operator &() { return &self; }
	LDKKeysInterface* operator ->() { return &self; }
	const LDKKeysInterface* operator &() const { return &self; }
	const LDKKeysInterface* operator ->() const { return &self; }
};
class InMemoryChannelKeys {
private:
	LDKInMemoryChannelKeys self;
public:
	InMemoryChannelKeys(const InMemoryChannelKeys&) = delete;
	InMemoryChannelKeys(InMemoryChannelKeys&& o) : self(o.self) { memset(&o, 0, sizeof(InMemoryChannelKeys)); }
	InMemoryChannelKeys(LDKInMemoryChannelKeys&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInMemoryChannelKeys)); }
	operator LDKInMemoryChannelKeys() && { LDKInMemoryChannelKeys res = self; memset(&self, 0, sizeof(LDKInMemoryChannelKeys)); return res; }
	~InMemoryChannelKeys() { InMemoryChannelKeys_free(self); }
	InMemoryChannelKeys& operator=(InMemoryChannelKeys&& o) { InMemoryChannelKeys_free(self); self = o.self; memset(&o, 0, sizeof(InMemoryChannelKeys)); return *this; }
	LDKInMemoryChannelKeys* operator &() { return &self; }
	LDKInMemoryChannelKeys* operator ->() { return &self; }
	const LDKInMemoryChannelKeys* operator &() const { return &self; }
	const LDKInMemoryChannelKeys* operator ->() const { return &self; }
};
class KeysManager {
private:
	LDKKeysManager self;
public:
	KeysManager(const KeysManager&) = delete;
	KeysManager(KeysManager&& o) : self(o.self) { memset(&o, 0, sizeof(KeysManager)); }
	KeysManager(LDKKeysManager&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKKeysManager)); }
	operator LDKKeysManager() && { LDKKeysManager res = self; memset(&self, 0, sizeof(LDKKeysManager)); return res; }
	~KeysManager() { KeysManager_free(self); }
	KeysManager& operator=(KeysManager&& o) { KeysManager_free(self); self = o.self; memset(&o, 0, sizeof(KeysManager)); return *this; }
	LDKKeysManager* operator &() { return &self; }
	LDKKeysManager* operator ->() { return &self; }
	const LDKKeysManager* operator &() const { return &self; }
	const LDKKeysManager* operator ->() const { return &self; }
};
class AccessError {
private:
	LDKAccessError self;
public:
	AccessError(const AccessError&) = delete;
	AccessError(AccessError&& o) : self(o.self) { memset(&o, 0, sizeof(AccessError)); }
	AccessError(LDKAccessError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAccessError)); }
	operator LDKAccessError() && { LDKAccessError res = self; memset(&self, 0, sizeof(LDKAccessError)); return res; }
	AccessError& operator=(AccessError&& o) { self = o.self; memset(&o, 0, sizeof(AccessError)); return *this; }
	LDKAccessError* operator &() { return &self; }
	LDKAccessError* operator ->() { return &self; }
	const LDKAccessError* operator &() const { return &self; }
	const LDKAccessError* operator ->() const { return &self; }
};
class Access {
private:
	LDKAccess self;
public:
	Access(const Access&) = delete;
	Access(Access&& o) : self(o.self) { memset(&o, 0, sizeof(Access)); }
	Access(LDKAccess&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAccess)); }
	operator LDKAccess() && { LDKAccess res = self; memset(&self, 0, sizeof(LDKAccess)); return res; }
	~Access() { Access_free(self); }
	Access& operator=(Access&& o) { Access_free(self); self = o.self; memset(&o, 0, sizeof(Access)); return *this; }
	LDKAccess* operator &() { return &self; }
	LDKAccess* operator ->() { return &self; }
	const LDKAccess* operator &() const { return &self; }
	const LDKAccess* operator ->() const { return &self; }
};
class Watch {
private:
	LDKWatch self;
public:
	Watch(const Watch&) = delete;
	Watch(Watch&& o) : self(o.self) { memset(&o, 0, sizeof(Watch)); }
	Watch(LDKWatch&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKWatch)); }
	operator LDKWatch() && { LDKWatch res = self; memset(&self, 0, sizeof(LDKWatch)); return res; }
	~Watch() { Watch_free(self); }
	Watch& operator=(Watch&& o) { Watch_free(self); self = o.self; memset(&o, 0, sizeof(Watch)); return *this; }
	LDKWatch* operator &() { return &self; }
	LDKWatch* operator ->() { return &self; }
	const LDKWatch* operator &() const { return &self; }
	const LDKWatch* operator ->() const { return &self; }
};
class Filter {
private:
	LDKFilter self;
public:
	Filter(const Filter&) = delete;
	Filter(Filter&& o) : self(o.self) { memset(&o, 0, sizeof(Filter)); }
	Filter(LDKFilter&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFilter)); }
	operator LDKFilter() && { LDKFilter res = self; memset(&self, 0, sizeof(LDKFilter)); return res; }
	~Filter() { Filter_free(self); }
	Filter& operator=(Filter&& o) { Filter_free(self); self = o.self; memset(&o, 0, sizeof(Filter)); return *this; }
	LDKFilter* operator &() { return &self; }
	LDKFilter* operator ->() { return &self; }
	const LDKFilter* operator &() const { return &self; }
	const LDKFilter* operator ->() const { return &self; }
};
class ChannelManager {
private:
	LDKChannelManager self;
public:
	ChannelManager(const ChannelManager&) = delete;
	ChannelManager(ChannelManager&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelManager)); }
	ChannelManager(LDKChannelManager&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelManager)); }
	operator LDKChannelManager() && { LDKChannelManager res = self; memset(&self, 0, sizeof(LDKChannelManager)); return res; }
	~ChannelManager() { ChannelManager_free(self); }
	ChannelManager& operator=(ChannelManager&& o) { ChannelManager_free(self); self = o.self; memset(&o, 0, sizeof(ChannelManager)); return *this; }
	LDKChannelManager* operator &() { return &self; }
	LDKChannelManager* operator ->() { return &self; }
	const LDKChannelManager* operator &() const { return &self; }
	const LDKChannelManager* operator ->() const { return &self; }
};
class ChannelDetails {
private:
	LDKChannelDetails self;
public:
	ChannelDetails(const ChannelDetails&) = delete;
	ChannelDetails(ChannelDetails&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelDetails)); }
	ChannelDetails(LDKChannelDetails&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelDetails)); }
	operator LDKChannelDetails() && { LDKChannelDetails res = self; memset(&self, 0, sizeof(LDKChannelDetails)); return res; }
	~ChannelDetails() { ChannelDetails_free(self); }
	ChannelDetails& operator=(ChannelDetails&& o) { ChannelDetails_free(self); self = o.self; memset(&o, 0, sizeof(ChannelDetails)); return *this; }
	LDKChannelDetails* operator &() { return &self; }
	LDKChannelDetails* operator ->() { return &self; }
	const LDKChannelDetails* operator &() const { return &self; }
	const LDKChannelDetails* operator ->() const { return &self; }
};
class PaymentSendFailure {
private:
	LDKPaymentSendFailure self;
public:
	PaymentSendFailure(const PaymentSendFailure&) = delete;
	PaymentSendFailure(PaymentSendFailure&& o) : self(o.self) { memset(&o, 0, sizeof(PaymentSendFailure)); }
	PaymentSendFailure(LDKPaymentSendFailure&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPaymentSendFailure)); }
	operator LDKPaymentSendFailure() && { LDKPaymentSendFailure res = self; memset(&self, 0, sizeof(LDKPaymentSendFailure)); return res; }
	~PaymentSendFailure() { PaymentSendFailure_free(self); }
	PaymentSendFailure& operator=(PaymentSendFailure&& o) { PaymentSendFailure_free(self); self = o.self; memset(&o, 0, sizeof(PaymentSendFailure)); return *this; }
	LDKPaymentSendFailure* operator &() { return &self; }
	LDKPaymentSendFailure* operator ->() { return &self; }
	const LDKPaymentSendFailure* operator &() const { return &self; }
	const LDKPaymentSendFailure* operator ->() const { return &self; }
};
class ChannelManagerReadArgs {
private:
	LDKChannelManagerReadArgs self;
public:
	ChannelManagerReadArgs(const ChannelManagerReadArgs&) = delete;
	ChannelManagerReadArgs(ChannelManagerReadArgs&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelManagerReadArgs)); }
	ChannelManagerReadArgs(LDKChannelManagerReadArgs&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelManagerReadArgs)); }
	operator LDKChannelManagerReadArgs() && { LDKChannelManagerReadArgs res = self; memset(&self, 0, sizeof(LDKChannelManagerReadArgs)); return res; }
	~ChannelManagerReadArgs() { ChannelManagerReadArgs_free(self); }
	ChannelManagerReadArgs& operator=(ChannelManagerReadArgs&& o) { ChannelManagerReadArgs_free(self); self = o.self; memset(&o, 0, sizeof(ChannelManagerReadArgs)); return *this; }
	LDKChannelManagerReadArgs* operator &() { return &self; }
	LDKChannelManagerReadArgs* operator ->() { return &self; }
	const LDKChannelManagerReadArgs* operator &() const { return &self; }
	const LDKChannelManagerReadArgs* operator ->() const { return &self; }
};
class DecodeError {
private:
	LDKDecodeError self;
public:
	DecodeError(const DecodeError&) = delete;
	DecodeError(DecodeError&& o) : self(o.self) { memset(&o, 0, sizeof(DecodeError)); }
	DecodeError(LDKDecodeError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDecodeError)); }
	operator LDKDecodeError() && { LDKDecodeError res = self; memset(&self, 0, sizeof(LDKDecodeError)); return res; }
	~DecodeError() { DecodeError_free(self); }
	DecodeError& operator=(DecodeError&& o) { DecodeError_free(self); self = o.self; memset(&o, 0, sizeof(DecodeError)); return *this; }
	LDKDecodeError* operator &() { return &self; }
	LDKDecodeError* operator ->() { return &self; }
	const LDKDecodeError* operator &() const { return &self; }
	const LDKDecodeError* operator ->() const { return &self; }
};
class Init {
private:
	LDKInit self;
public:
	Init(const Init&) = delete;
	Init(Init&& o) : self(o.self) { memset(&o, 0, sizeof(Init)); }
	Init(LDKInit&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInit)); }
	operator LDKInit() && { LDKInit res = self; memset(&self, 0, sizeof(LDKInit)); return res; }
	~Init() { Init_free(self); }
	Init& operator=(Init&& o) { Init_free(self); self = o.self; memset(&o, 0, sizeof(Init)); return *this; }
	LDKInit* operator &() { return &self; }
	LDKInit* operator ->() { return &self; }
	const LDKInit* operator &() const { return &self; }
	const LDKInit* operator ->() const { return &self; }
};
class ErrorMessage {
private:
	LDKErrorMessage self;
public:
	ErrorMessage(const ErrorMessage&) = delete;
	ErrorMessage(ErrorMessage&& o) : self(o.self) { memset(&o, 0, sizeof(ErrorMessage)); }
	ErrorMessage(LDKErrorMessage&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKErrorMessage)); }
	operator LDKErrorMessage() && { LDKErrorMessage res = self; memset(&self, 0, sizeof(LDKErrorMessage)); return res; }
	~ErrorMessage() { ErrorMessage_free(self); }
	ErrorMessage& operator=(ErrorMessage&& o) { ErrorMessage_free(self); self = o.self; memset(&o, 0, sizeof(ErrorMessage)); return *this; }
	LDKErrorMessage* operator &() { return &self; }
	LDKErrorMessage* operator ->() { return &self; }
	const LDKErrorMessage* operator &() const { return &self; }
	const LDKErrorMessage* operator ->() const { return &self; }
};
class Ping {
private:
	LDKPing self;
public:
	Ping(const Ping&) = delete;
	Ping(Ping&& o) : self(o.self) { memset(&o, 0, sizeof(Ping)); }
	Ping(LDKPing&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPing)); }
	operator LDKPing() && { LDKPing res = self; memset(&self, 0, sizeof(LDKPing)); return res; }
	~Ping() { Ping_free(self); }
	Ping& operator=(Ping&& o) { Ping_free(self); self = o.self; memset(&o, 0, sizeof(Ping)); return *this; }
	LDKPing* operator &() { return &self; }
	LDKPing* operator ->() { return &self; }
	const LDKPing* operator &() const { return &self; }
	const LDKPing* operator ->() const { return &self; }
};
class Pong {
private:
	LDKPong self;
public:
	Pong(const Pong&) = delete;
	Pong(Pong&& o) : self(o.self) { memset(&o, 0, sizeof(Pong)); }
	Pong(LDKPong&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPong)); }
	operator LDKPong() && { LDKPong res = self; memset(&self, 0, sizeof(LDKPong)); return res; }
	~Pong() { Pong_free(self); }
	Pong& operator=(Pong&& o) { Pong_free(self); self = o.self; memset(&o, 0, sizeof(Pong)); return *this; }
	LDKPong* operator &() { return &self; }
	LDKPong* operator ->() { return &self; }
	const LDKPong* operator &() const { return &self; }
	const LDKPong* operator ->() const { return &self; }
};
class OpenChannel {
private:
	LDKOpenChannel self;
public:
	OpenChannel(const OpenChannel&) = delete;
	OpenChannel(OpenChannel&& o) : self(o.self) { memset(&o, 0, sizeof(OpenChannel)); }
	OpenChannel(LDKOpenChannel&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKOpenChannel)); }
	operator LDKOpenChannel() && { LDKOpenChannel res = self; memset(&self, 0, sizeof(LDKOpenChannel)); return res; }
	~OpenChannel() { OpenChannel_free(self); }
	OpenChannel& operator=(OpenChannel&& o) { OpenChannel_free(self); self = o.self; memset(&o, 0, sizeof(OpenChannel)); return *this; }
	LDKOpenChannel* operator &() { return &self; }
	LDKOpenChannel* operator ->() { return &self; }
	const LDKOpenChannel* operator &() const { return &self; }
	const LDKOpenChannel* operator ->() const { return &self; }
};
class AcceptChannel {
private:
	LDKAcceptChannel self;
public:
	AcceptChannel(const AcceptChannel&) = delete;
	AcceptChannel(AcceptChannel&& o) : self(o.self) { memset(&o, 0, sizeof(AcceptChannel)); }
	AcceptChannel(LDKAcceptChannel&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAcceptChannel)); }
	operator LDKAcceptChannel() && { LDKAcceptChannel res = self; memset(&self, 0, sizeof(LDKAcceptChannel)); return res; }
	~AcceptChannel() { AcceptChannel_free(self); }
	AcceptChannel& operator=(AcceptChannel&& o) { AcceptChannel_free(self); self = o.self; memset(&o, 0, sizeof(AcceptChannel)); return *this; }
	LDKAcceptChannel* operator &() { return &self; }
	LDKAcceptChannel* operator ->() { return &self; }
	const LDKAcceptChannel* operator &() const { return &self; }
	const LDKAcceptChannel* operator ->() const { return &self; }
};
class FundingCreated {
private:
	LDKFundingCreated self;
public:
	FundingCreated(const FundingCreated&) = delete;
	FundingCreated(FundingCreated&& o) : self(o.self) { memset(&o, 0, sizeof(FundingCreated)); }
	FundingCreated(LDKFundingCreated&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFundingCreated)); }
	operator LDKFundingCreated() && { LDKFundingCreated res = self; memset(&self, 0, sizeof(LDKFundingCreated)); return res; }
	~FundingCreated() { FundingCreated_free(self); }
	FundingCreated& operator=(FundingCreated&& o) { FundingCreated_free(self); self = o.self; memset(&o, 0, sizeof(FundingCreated)); return *this; }
	LDKFundingCreated* operator &() { return &self; }
	LDKFundingCreated* operator ->() { return &self; }
	const LDKFundingCreated* operator &() const { return &self; }
	const LDKFundingCreated* operator ->() const { return &self; }
};
class FundingSigned {
private:
	LDKFundingSigned self;
public:
	FundingSigned(const FundingSigned&) = delete;
	FundingSigned(FundingSigned&& o) : self(o.self) { memset(&o, 0, sizeof(FundingSigned)); }
	FundingSigned(LDKFundingSigned&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFundingSigned)); }
	operator LDKFundingSigned() && { LDKFundingSigned res = self; memset(&self, 0, sizeof(LDKFundingSigned)); return res; }
	~FundingSigned() { FundingSigned_free(self); }
	FundingSigned& operator=(FundingSigned&& o) { FundingSigned_free(self); self = o.self; memset(&o, 0, sizeof(FundingSigned)); return *this; }
	LDKFundingSigned* operator &() { return &self; }
	LDKFundingSigned* operator ->() { return &self; }
	const LDKFundingSigned* operator &() const { return &self; }
	const LDKFundingSigned* operator ->() const { return &self; }
};
class FundingLocked {
private:
	LDKFundingLocked self;
public:
	FundingLocked(const FundingLocked&) = delete;
	FundingLocked(FundingLocked&& o) : self(o.self) { memset(&o, 0, sizeof(FundingLocked)); }
	FundingLocked(LDKFundingLocked&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKFundingLocked)); }
	operator LDKFundingLocked() && { LDKFundingLocked res = self; memset(&self, 0, sizeof(LDKFundingLocked)); return res; }
	~FundingLocked() { FundingLocked_free(self); }
	FundingLocked& operator=(FundingLocked&& o) { FundingLocked_free(self); self = o.self; memset(&o, 0, sizeof(FundingLocked)); return *this; }
	LDKFundingLocked* operator &() { return &self; }
	LDKFundingLocked* operator ->() { return &self; }
	const LDKFundingLocked* operator &() const { return &self; }
	const LDKFundingLocked* operator ->() const { return &self; }
};
class Shutdown {
private:
	LDKShutdown self;
public:
	Shutdown(const Shutdown&) = delete;
	Shutdown(Shutdown&& o) : self(o.self) { memset(&o, 0, sizeof(Shutdown)); }
	Shutdown(LDKShutdown&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKShutdown)); }
	operator LDKShutdown() && { LDKShutdown res = self; memset(&self, 0, sizeof(LDKShutdown)); return res; }
	~Shutdown() { Shutdown_free(self); }
	Shutdown& operator=(Shutdown&& o) { Shutdown_free(self); self = o.self; memset(&o, 0, sizeof(Shutdown)); return *this; }
	LDKShutdown* operator &() { return &self; }
	LDKShutdown* operator ->() { return &self; }
	const LDKShutdown* operator &() const { return &self; }
	const LDKShutdown* operator ->() const { return &self; }
};
class ClosingSigned {
private:
	LDKClosingSigned self;
public:
	ClosingSigned(const ClosingSigned&) = delete;
	ClosingSigned(ClosingSigned&& o) : self(o.self) { memset(&o, 0, sizeof(ClosingSigned)); }
	ClosingSigned(LDKClosingSigned&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKClosingSigned)); }
	operator LDKClosingSigned() && { LDKClosingSigned res = self; memset(&self, 0, sizeof(LDKClosingSigned)); return res; }
	~ClosingSigned() { ClosingSigned_free(self); }
	ClosingSigned& operator=(ClosingSigned&& o) { ClosingSigned_free(self); self = o.self; memset(&o, 0, sizeof(ClosingSigned)); return *this; }
	LDKClosingSigned* operator &() { return &self; }
	LDKClosingSigned* operator ->() { return &self; }
	const LDKClosingSigned* operator &() const { return &self; }
	const LDKClosingSigned* operator ->() const { return &self; }
};
class UpdateAddHTLC {
private:
	LDKUpdateAddHTLC self;
public:
	UpdateAddHTLC(const UpdateAddHTLC&) = delete;
	UpdateAddHTLC(UpdateAddHTLC&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateAddHTLC)); }
	UpdateAddHTLC(LDKUpdateAddHTLC&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateAddHTLC)); }
	operator LDKUpdateAddHTLC() && { LDKUpdateAddHTLC res = self; memset(&self, 0, sizeof(LDKUpdateAddHTLC)); return res; }
	~UpdateAddHTLC() { UpdateAddHTLC_free(self); }
	UpdateAddHTLC& operator=(UpdateAddHTLC&& o) { UpdateAddHTLC_free(self); self = o.self; memset(&o, 0, sizeof(UpdateAddHTLC)); return *this; }
	LDKUpdateAddHTLC* operator &() { return &self; }
	LDKUpdateAddHTLC* operator ->() { return &self; }
	const LDKUpdateAddHTLC* operator &() const { return &self; }
	const LDKUpdateAddHTLC* operator ->() const { return &self; }
};
class UpdateFulfillHTLC {
private:
	LDKUpdateFulfillHTLC self;
public:
	UpdateFulfillHTLC(const UpdateFulfillHTLC&) = delete;
	UpdateFulfillHTLC(UpdateFulfillHTLC&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateFulfillHTLC)); }
	UpdateFulfillHTLC(LDKUpdateFulfillHTLC&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateFulfillHTLC)); }
	operator LDKUpdateFulfillHTLC() && { LDKUpdateFulfillHTLC res = self; memset(&self, 0, sizeof(LDKUpdateFulfillHTLC)); return res; }
	~UpdateFulfillHTLC() { UpdateFulfillHTLC_free(self); }
	UpdateFulfillHTLC& operator=(UpdateFulfillHTLC&& o) { UpdateFulfillHTLC_free(self); self = o.self; memset(&o, 0, sizeof(UpdateFulfillHTLC)); return *this; }
	LDKUpdateFulfillHTLC* operator &() { return &self; }
	LDKUpdateFulfillHTLC* operator ->() { return &self; }
	const LDKUpdateFulfillHTLC* operator &() const { return &self; }
	const LDKUpdateFulfillHTLC* operator ->() const { return &self; }
};
class UpdateFailHTLC {
private:
	LDKUpdateFailHTLC self;
public:
	UpdateFailHTLC(const UpdateFailHTLC&) = delete;
	UpdateFailHTLC(UpdateFailHTLC&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateFailHTLC)); }
	UpdateFailHTLC(LDKUpdateFailHTLC&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateFailHTLC)); }
	operator LDKUpdateFailHTLC() && { LDKUpdateFailHTLC res = self; memset(&self, 0, sizeof(LDKUpdateFailHTLC)); return res; }
	~UpdateFailHTLC() { UpdateFailHTLC_free(self); }
	UpdateFailHTLC& operator=(UpdateFailHTLC&& o) { UpdateFailHTLC_free(self); self = o.self; memset(&o, 0, sizeof(UpdateFailHTLC)); return *this; }
	LDKUpdateFailHTLC* operator &() { return &self; }
	LDKUpdateFailHTLC* operator ->() { return &self; }
	const LDKUpdateFailHTLC* operator &() const { return &self; }
	const LDKUpdateFailHTLC* operator ->() const { return &self; }
};
class UpdateFailMalformedHTLC {
private:
	LDKUpdateFailMalformedHTLC self;
public:
	UpdateFailMalformedHTLC(const UpdateFailMalformedHTLC&) = delete;
	UpdateFailMalformedHTLC(UpdateFailMalformedHTLC&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateFailMalformedHTLC)); }
	UpdateFailMalformedHTLC(LDKUpdateFailMalformedHTLC&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateFailMalformedHTLC)); }
	operator LDKUpdateFailMalformedHTLC() && { LDKUpdateFailMalformedHTLC res = self; memset(&self, 0, sizeof(LDKUpdateFailMalformedHTLC)); return res; }
	~UpdateFailMalformedHTLC() { UpdateFailMalformedHTLC_free(self); }
	UpdateFailMalformedHTLC& operator=(UpdateFailMalformedHTLC&& o) { UpdateFailMalformedHTLC_free(self); self = o.self; memset(&o, 0, sizeof(UpdateFailMalformedHTLC)); return *this; }
	LDKUpdateFailMalformedHTLC* operator &() { return &self; }
	LDKUpdateFailMalformedHTLC* operator ->() { return &self; }
	const LDKUpdateFailMalformedHTLC* operator &() const { return &self; }
	const LDKUpdateFailMalformedHTLC* operator ->() const { return &self; }
};
class CommitmentSigned {
private:
	LDKCommitmentSigned self;
public:
	CommitmentSigned(const CommitmentSigned&) = delete;
	CommitmentSigned(CommitmentSigned&& o) : self(o.self) { memset(&o, 0, sizeof(CommitmentSigned)); }
	CommitmentSigned(LDKCommitmentSigned&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCommitmentSigned)); }
	operator LDKCommitmentSigned() && { LDKCommitmentSigned res = self; memset(&self, 0, sizeof(LDKCommitmentSigned)); return res; }
	~CommitmentSigned() { CommitmentSigned_free(self); }
	CommitmentSigned& operator=(CommitmentSigned&& o) { CommitmentSigned_free(self); self = o.self; memset(&o, 0, sizeof(CommitmentSigned)); return *this; }
	LDKCommitmentSigned* operator &() { return &self; }
	LDKCommitmentSigned* operator ->() { return &self; }
	const LDKCommitmentSigned* operator &() const { return &self; }
	const LDKCommitmentSigned* operator ->() const { return &self; }
};
class RevokeAndACK {
private:
	LDKRevokeAndACK self;
public:
	RevokeAndACK(const RevokeAndACK&) = delete;
	RevokeAndACK(RevokeAndACK&& o) : self(o.self) { memset(&o, 0, sizeof(RevokeAndACK)); }
	RevokeAndACK(LDKRevokeAndACK&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRevokeAndACK)); }
	operator LDKRevokeAndACK() && { LDKRevokeAndACK res = self; memset(&self, 0, sizeof(LDKRevokeAndACK)); return res; }
	~RevokeAndACK() { RevokeAndACK_free(self); }
	RevokeAndACK& operator=(RevokeAndACK&& o) { RevokeAndACK_free(self); self = o.self; memset(&o, 0, sizeof(RevokeAndACK)); return *this; }
	LDKRevokeAndACK* operator &() { return &self; }
	LDKRevokeAndACK* operator ->() { return &self; }
	const LDKRevokeAndACK* operator &() const { return &self; }
	const LDKRevokeAndACK* operator ->() const { return &self; }
};
class UpdateFee {
private:
	LDKUpdateFee self;
public:
	UpdateFee(const UpdateFee&) = delete;
	UpdateFee(UpdateFee&& o) : self(o.self) { memset(&o, 0, sizeof(UpdateFee)); }
	UpdateFee(LDKUpdateFee&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUpdateFee)); }
	operator LDKUpdateFee() && { LDKUpdateFee res = self; memset(&self, 0, sizeof(LDKUpdateFee)); return res; }
	~UpdateFee() { UpdateFee_free(self); }
	UpdateFee& operator=(UpdateFee&& o) { UpdateFee_free(self); self = o.self; memset(&o, 0, sizeof(UpdateFee)); return *this; }
	LDKUpdateFee* operator &() { return &self; }
	LDKUpdateFee* operator ->() { return &self; }
	const LDKUpdateFee* operator &() const { return &self; }
	const LDKUpdateFee* operator ->() const { return &self; }
};
class DataLossProtect {
private:
	LDKDataLossProtect self;
public:
	DataLossProtect(const DataLossProtect&) = delete;
	DataLossProtect(DataLossProtect&& o) : self(o.self) { memset(&o, 0, sizeof(DataLossProtect)); }
	DataLossProtect(LDKDataLossProtect&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDataLossProtect)); }
	operator LDKDataLossProtect() && { LDKDataLossProtect res = self; memset(&self, 0, sizeof(LDKDataLossProtect)); return res; }
	~DataLossProtect() { DataLossProtect_free(self); }
	DataLossProtect& operator=(DataLossProtect&& o) { DataLossProtect_free(self); self = o.self; memset(&o, 0, sizeof(DataLossProtect)); return *this; }
	LDKDataLossProtect* operator &() { return &self; }
	LDKDataLossProtect* operator ->() { return &self; }
	const LDKDataLossProtect* operator &() const { return &self; }
	const LDKDataLossProtect* operator ->() const { return &self; }
};
class ChannelReestablish {
private:
	LDKChannelReestablish self;
public:
	ChannelReestablish(const ChannelReestablish&) = delete;
	ChannelReestablish(ChannelReestablish&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelReestablish)); }
	ChannelReestablish(LDKChannelReestablish&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelReestablish)); }
	operator LDKChannelReestablish() && { LDKChannelReestablish res = self; memset(&self, 0, sizeof(LDKChannelReestablish)); return res; }
	~ChannelReestablish() { ChannelReestablish_free(self); }
	ChannelReestablish& operator=(ChannelReestablish&& o) { ChannelReestablish_free(self); self = o.self; memset(&o, 0, sizeof(ChannelReestablish)); return *this; }
	LDKChannelReestablish* operator &() { return &self; }
	LDKChannelReestablish* operator ->() { return &self; }
	const LDKChannelReestablish* operator &() const { return &self; }
	const LDKChannelReestablish* operator ->() const { return &self; }
};
class AnnouncementSignatures {
private:
	LDKAnnouncementSignatures self;
public:
	AnnouncementSignatures(const AnnouncementSignatures&) = delete;
	AnnouncementSignatures(AnnouncementSignatures&& o) : self(o.self) { memset(&o, 0, sizeof(AnnouncementSignatures)); }
	AnnouncementSignatures(LDKAnnouncementSignatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKAnnouncementSignatures)); }
	operator LDKAnnouncementSignatures() && { LDKAnnouncementSignatures res = self; memset(&self, 0, sizeof(LDKAnnouncementSignatures)); return res; }
	~AnnouncementSignatures() { AnnouncementSignatures_free(self); }
	AnnouncementSignatures& operator=(AnnouncementSignatures&& o) { AnnouncementSignatures_free(self); self = o.self; memset(&o, 0, sizeof(AnnouncementSignatures)); return *this; }
	LDKAnnouncementSignatures* operator &() { return &self; }
	LDKAnnouncementSignatures* operator ->() { return &self; }
	const LDKAnnouncementSignatures* operator &() const { return &self; }
	const LDKAnnouncementSignatures* operator ->() const { return &self; }
};
class NetAddress {
private:
	LDKNetAddress self;
public:
	NetAddress(const NetAddress&) = delete;
	NetAddress(NetAddress&& o) : self(o.self) { memset(&o, 0, sizeof(NetAddress)); }
	NetAddress(LDKNetAddress&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNetAddress)); }
	operator LDKNetAddress() && { LDKNetAddress res = self; memset(&self, 0, sizeof(LDKNetAddress)); return res; }
	~NetAddress() { NetAddress_free(self); }
	NetAddress& operator=(NetAddress&& o) { NetAddress_free(self); self = o.self; memset(&o, 0, sizeof(NetAddress)); return *this; }
	LDKNetAddress* operator &() { return &self; }
	LDKNetAddress* operator ->() { return &self; }
	const LDKNetAddress* operator &() const { return &self; }
	const LDKNetAddress* operator ->() const { return &self; }
};
class UnsignedNodeAnnouncement {
private:
	LDKUnsignedNodeAnnouncement self;
public:
	UnsignedNodeAnnouncement(const UnsignedNodeAnnouncement&) = delete;
	UnsignedNodeAnnouncement(UnsignedNodeAnnouncement&& o) : self(o.self) { memset(&o, 0, sizeof(UnsignedNodeAnnouncement)); }
	UnsignedNodeAnnouncement(LDKUnsignedNodeAnnouncement&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUnsignedNodeAnnouncement)); }
	operator LDKUnsignedNodeAnnouncement() && { LDKUnsignedNodeAnnouncement res = self; memset(&self, 0, sizeof(LDKUnsignedNodeAnnouncement)); return res; }
	~UnsignedNodeAnnouncement() { UnsignedNodeAnnouncement_free(self); }
	UnsignedNodeAnnouncement& operator=(UnsignedNodeAnnouncement&& o) { UnsignedNodeAnnouncement_free(self); self = o.self; memset(&o, 0, sizeof(UnsignedNodeAnnouncement)); return *this; }
	LDKUnsignedNodeAnnouncement* operator &() { return &self; }
	LDKUnsignedNodeAnnouncement* operator ->() { return &self; }
	const LDKUnsignedNodeAnnouncement* operator &() const { return &self; }
	const LDKUnsignedNodeAnnouncement* operator ->() const { return &self; }
};
class NodeAnnouncement {
private:
	LDKNodeAnnouncement self;
public:
	NodeAnnouncement(const NodeAnnouncement&) = delete;
	NodeAnnouncement(NodeAnnouncement&& o) : self(o.self) { memset(&o, 0, sizeof(NodeAnnouncement)); }
	NodeAnnouncement(LDKNodeAnnouncement&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeAnnouncement)); }
	operator LDKNodeAnnouncement() && { LDKNodeAnnouncement res = self; memset(&self, 0, sizeof(LDKNodeAnnouncement)); return res; }
	~NodeAnnouncement() { NodeAnnouncement_free(self); }
	NodeAnnouncement& operator=(NodeAnnouncement&& o) { NodeAnnouncement_free(self); self = o.self; memset(&o, 0, sizeof(NodeAnnouncement)); return *this; }
	LDKNodeAnnouncement* operator &() { return &self; }
	LDKNodeAnnouncement* operator ->() { return &self; }
	const LDKNodeAnnouncement* operator &() const { return &self; }
	const LDKNodeAnnouncement* operator ->() const { return &self; }
};
class UnsignedChannelAnnouncement {
private:
	LDKUnsignedChannelAnnouncement self;
public:
	UnsignedChannelAnnouncement(const UnsignedChannelAnnouncement&) = delete;
	UnsignedChannelAnnouncement(UnsignedChannelAnnouncement&& o) : self(o.self) { memset(&o, 0, sizeof(UnsignedChannelAnnouncement)); }
	UnsignedChannelAnnouncement(LDKUnsignedChannelAnnouncement&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUnsignedChannelAnnouncement)); }
	operator LDKUnsignedChannelAnnouncement() && { LDKUnsignedChannelAnnouncement res = self; memset(&self, 0, sizeof(LDKUnsignedChannelAnnouncement)); return res; }
	~UnsignedChannelAnnouncement() { UnsignedChannelAnnouncement_free(self); }
	UnsignedChannelAnnouncement& operator=(UnsignedChannelAnnouncement&& o) { UnsignedChannelAnnouncement_free(self); self = o.self; memset(&o, 0, sizeof(UnsignedChannelAnnouncement)); return *this; }
	LDKUnsignedChannelAnnouncement* operator &() { return &self; }
	LDKUnsignedChannelAnnouncement* operator ->() { return &self; }
	const LDKUnsignedChannelAnnouncement* operator &() const { return &self; }
	const LDKUnsignedChannelAnnouncement* operator ->() const { return &self; }
};
class ChannelAnnouncement {
private:
	LDKChannelAnnouncement self;
public:
	ChannelAnnouncement(const ChannelAnnouncement&) = delete;
	ChannelAnnouncement(ChannelAnnouncement&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelAnnouncement)); }
	ChannelAnnouncement(LDKChannelAnnouncement&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelAnnouncement)); }
	operator LDKChannelAnnouncement() && { LDKChannelAnnouncement res = self; memset(&self, 0, sizeof(LDKChannelAnnouncement)); return res; }
	~ChannelAnnouncement() { ChannelAnnouncement_free(self); }
	ChannelAnnouncement& operator=(ChannelAnnouncement&& o) { ChannelAnnouncement_free(self); self = o.self; memset(&o, 0, sizeof(ChannelAnnouncement)); return *this; }
	LDKChannelAnnouncement* operator &() { return &self; }
	LDKChannelAnnouncement* operator ->() { return &self; }
	const LDKChannelAnnouncement* operator &() const { return &self; }
	const LDKChannelAnnouncement* operator ->() const { return &self; }
};
class UnsignedChannelUpdate {
private:
	LDKUnsignedChannelUpdate self;
public:
	UnsignedChannelUpdate(const UnsignedChannelUpdate&) = delete;
	UnsignedChannelUpdate(UnsignedChannelUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(UnsignedChannelUpdate)); }
	UnsignedChannelUpdate(LDKUnsignedChannelUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKUnsignedChannelUpdate)); }
	operator LDKUnsignedChannelUpdate() && { LDKUnsignedChannelUpdate res = self; memset(&self, 0, sizeof(LDKUnsignedChannelUpdate)); return res; }
	~UnsignedChannelUpdate() { UnsignedChannelUpdate_free(self); }
	UnsignedChannelUpdate& operator=(UnsignedChannelUpdate&& o) { UnsignedChannelUpdate_free(self); self = o.self; memset(&o, 0, sizeof(UnsignedChannelUpdate)); return *this; }
	LDKUnsignedChannelUpdate* operator &() { return &self; }
	LDKUnsignedChannelUpdate* operator ->() { return &self; }
	const LDKUnsignedChannelUpdate* operator &() const { return &self; }
	const LDKUnsignedChannelUpdate* operator ->() const { return &self; }
};
class ChannelUpdate {
private:
	LDKChannelUpdate self;
public:
	ChannelUpdate(const ChannelUpdate&) = delete;
	ChannelUpdate(ChannelUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelUpdate)); }
	ChannelUpdate(LDKChannelUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelUpdate)); }
	operator LDKChannelUpdate() && { LDKChannelUpdate res = self; memset(&self, 0, sizeof(LDKChannelUpdate)); return res; }
	~ChannelUpdate() { ChannelUpdate_free(self); }
	ChannelUpdate& operator=(ChannelUpdate&& o) { ChannelUpdate_free(self); self = o.self; memset(&o, 0, sizeof(ChannelUpdate)); return *this; }
	LDKChannelUpdate* operator &() { return &self; }
	LDKChannelUpdate* operator ->() { return &self; }
	const LDKChannelUpdate* operator &() const { return &self; }
	const LDKChannelUpdate* operator ->() const { return &self; }
};
class QueryChannelRange {
private:
	LDKQueryChannelRange self;
public:
	QueryChannelRange(const QueryChannelRange&) = delete;
	QueryChannelRange(QueryChannelRange&& o) : self(o.self) { memset(&o, 0, sizeof(QueryChannelRange)); }
	QueryChannelRange(LDKQueryChannelRange&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKQueryChannelRange)); }
	operator LDKQueryChannelRange() && { LDKQueryChannelRange res = self; memset(&self, 0, sizeof(LDKQueryChannelRange)); return res; }
	~QueryChannelRange() { QueryChannelRange_free(self); }
	QueryChannelRange& operator=(QueryChannelRange&& o) { QueryChannelRange_free(self); self = o.self; memset(&o, 0, sizeof(QueryChannelRange)); return *this; }
	LDKQueryChannelRange* operator &() { return &self; }
	LDKQueryChannelRange* operator ->() { return &self; }
	const LDKQueryChannelRange* operator &() const { return &self; }
	const LDKQueryChannelRange* operator ->() const { return &self; }
};
class ReplyChannelRange {
private:
	LDKReplyChannelRange self;
public:
	ReplyChannelRange(const ReplyChannelRange&) = delete;
	ReplyChannelRange(ReplyChannelRange&& o) : self(o.self) { memset(&o, 0, sizeof(ReplyChannelRange)); }
	ReplyChannelRange(LDKReplyChannelRange&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKReplyChannelRange)); }
	operator LDKReplyChannelRange() && { LDKReplyChannelRange res = self; memset(&self, 0, sizeof(LDKReplyChannelRange)); return res; }
	~ReplyChannelRange() { ReplyChannelRange_free(self); }
	ReplyChannelRange& operator=(ReplyChannelRange&& o) { ReplyChannelRange_free(self); self = o.self; memset(&o, 0, sizeof(ReplyChannelRange)); return *this; }
	LDKReplyChannelRange* operator &() { return &self; }
	LDKReplyChannelRange* operator ->() { return &self; }
	const LDKReplyChannelRange* operator &() const { return &self; }
	const LDKReplyChannelRange* operator ->() const { return &self; }
};
class QueryShortChannelIds {
private:
	LDKQueryShortChannelIds self;
public:
	QueryShortChannelIds(const QueryShortChannelIds&) = delete;
	QueryShortChannelIds(QueryShortChannelIds&& o) : self(o.self) { memset(&o, 0, sizeof(QueryShortChannelIds)); }
	QueryShortChannelIds(LDKQueryShortChannelIds&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKQueryShortChannelIds)); }
	operator LDKQueryShortChannelIds() && { LDKQueryShortChannelIds res = self; memset(&self, 0, sizeof(LDKQueryShortChannelIds)); return res; }
	~QueryShortChannelIds() { QueryShortChannelIds_free(self); }
	QueryShortChannelIds& operator=(QueryShortChannelIds&& o) { QueryShortChannelIds_free(self); self = o.self; memset(&o, 0, sizeof(QueryShortChannelIds)); return *this; }
	LDKQueryShortChannelIds* operator &() { return &self; }
	LDKQueryShortChannelIds* operator ->() { return &self; }
	const LDKQueryShortChannelIds* operator &() const { return &self; }
	const LDKQueryShortChannelIds* operator ->() const { return &self; }
};
class ReplyShortChannelIdsEnd {
private:
	LDKReplyShortChannelIdsEnd self;
public:
	ReplyShortChannelIdsEnd(const ReplyShortChannelIdsEnd&) = delete;
	ReplyShortChannelIdsEnd(ReplyShortChannelIdsEnd&& o) : self(o.self) { memset(&o, 0, sizeof(ReplyShortChannelIdsEnd)); }
	ReplyShortChannelIdsEnd(LDKReplyShortChannelIdsEnd&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKReplyShortChannelIdsEnd)); }
	operator LDKReplyShortChannelIdsEnd() && { LDKReplyShortChannelIdsEnd res = self; memset(&self, 0, sizeof(LDKReplyShortChannelIdsEnd)); return res; }
	~ReplyShortChannelIdsEnd() { ReplyShortChannelIdsEnd_free(self); }
	ReplyShortChannelIdsEnd& operator=(ReplyShortChannelIdsEnd&& o) { ReplyShortChannelIdsEnd_free(self); self = o.self; memset(&o, 0, sizeof(ReplyShortChannelIdsEnd)); return *this; }
	LDKReplyShortChannelIdsEnd* operator &() { return &self; }
	LDKReplyShortChannelIdsEnd* operator ->() { return &self; }
	const LDKReplyShortChannelIdsEnd* operator &() const { return &self; }
	const LDKReplyShortChannelIdsEnd* operator ->() const { return &self; }
};
class GossipTimestampFilter {
private:
	LDKGossipTimestampFilter self;
public:
	GossipTimestampFilter(const GossipTimestampFilter&) = delete;
	GossipTimestampFilter(GossipTimestampFilter&& o) : self(o.self) { memset(&o, 0, sizeof(GossipTimestampFilter)); }
	GossipTimestampFilter(LDKGossipTimestampFilter&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKGossipTimestampFilter)); }
	operator LDKGossipTimestampFilter() && { LDKGossipTimestampFilter res = self; memset(&self, 0, sizeof(LDKGossipTimestampFilter)); return res; }
	~GossipTimestampFilter() { GossipTimestampFilter_free(self); }
	GossipTimestampFilter& operator=(GossipTimestampFilter&& o) { GossipTimestampFilter_free(self); self = o.self; memset(&o, 0, sizeof(GossipTimestampFilter)); return *this; }
	LDKGossipTimestampFilter* operator &() { return &self; }
	LDKGossipTimestampFilter* operator ->() { return &self; }
	const LDKGossipTimestampFilter* operator &() const { return &self; }
	const LDKGossipTimestampFilter* operator ->() const { return &self; }
};
class ErrorAction {
private:
	LDKErrorAction self;
public:
	ErrorAction(const ErrorAction&) = delete;
	ErrorAction(ErrorAction&& o) : self(o.self) { memset(&o, 0, sizeof(ErrorAction)); }
	ErrorAction(LDKErrorAction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKErrorAction)); }
	operator LDKErrorAction() && { LDKErrorAction res = self; memset(&self, 0, sizeof(LDKErrorAction)); return res; }
	~ErrorAction() { ErrorAction_free(self); }
	ErrorAction& operator=(ErrorAction&& o) { ErrorAction_free(self); self = o.self; memset(&o, 0, sizeof(ErrorAction)); return *this; }
	LDKErrorAction* operator &() { return &self; }
	LDKErrorAction* operator ->() { return &self; }
	const LDKErrorAction* operator &() const { return &self; }
	const LDKErrorAction* operator ->() const { return &self; }
};
class LightningError {
private:
	LDKLightningError self;
public:
	LightningError(const LightningError&) = delete;
	LightningError(LightningError&& o) : self(o.self) { memset(&o, 0, sizeof(LightningError)); }
	LightningError(LDKLightningError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKLightningError)); }
	operator LDKLightningError() && { LDKLightningError res = self; memset(&self, 0, sizeof(LDKLightningError)); return res; }
	~LightningError() { LightningError_free(self); }
	LightningError& operator=(LightningError&& o) { LightningError_free(self); self = o.self; memset(&o, 0, sizeof(LightningError)); return *this; }
	LDKLightningError* operator &() { return &self; }
	LDKLightningError* operator ->() { return &self; }
	const LDKLightningError* operator &() const { return &self; }
	const LDKLightningError* operator ->() const { return &self; }
};
class CommitmentUpdate {
private:
	LDKCommitmentUpdate self;
public:
	CommitmentUpdate(const CommitmentUpdate&) = delete;
	CommitmentUpdate(CommitmentUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(CommitmentUpdate)); }
	CommitmentUpdate(LDKCommitmentUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCommitmentUpdate)); }
	operator LDKCommitmentUpdate() && { LDKCommitmentUpdate res = self; memset(&self, 0, sizeof(LDKCommitmentUpdate)); return res; }
	~CommitmentUpdate() { CommitmentUpdate_free(self); }
	CommitmentUpdate& operator=(CommitmentUpdate&& o) { CommitmentUpdate_free(self); self = o.self; memset(&o, 0, sizeof(CommitmentUpdate)); return *this; }
	LDKCommitmentUpdate* operator &() { return &self; }
	LDKCommitmentUpdate* operator ->() { return &self; }
	const LDKCommitmentUpdate* operator &() const { return &self; }
	const LDKCommitmentUpdate* operator ->() const { return &self; }
};
class HTLCFailChannelUpdate {
private:
	LDKHTLCFailChannelUpdate self;
public:
	HTLCFailChannelUpdate(const HTLCFailChannelUpdate&) = delete;
	HTLCFailChannelUpdate(HTLCFailChannelUpdate&& o) : self(o.self) { memset(&o, 0, sizeof(HTLCFailChannelUpdate)); }
	HTLCFailChannelUpdate(LDKHTLCFailChannelUpdate&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKHTLCFailChannelUpdate)); }
	operator LDKHTLCFailChannelUpdate() && { LDKHTLCFailChannelUpdate res = self; memset(&self, 0, sizeof(LDKHTLCFailChannelUpdate)); return res; }
	~HTLCFailChannelUpdate() { HTLCFailChannelUpdate_free(self); }
	HTLCFailChannelUpdate& operator=(HTLCFailChannelUpdate&& o) { HTLCFailChannelUpdate_free(self); self = o.self; memset(&o, 0, sizeof(HTLCFailChannelUpdate)); return *this; }
	LDKHTLCFailChannelUpdate* operator &() { return &self; }
	LDKHTLCFailChannelUpdate* operator ->() { return &self; }
	const LDKHTLCFailChannelUpdate* operator &() const { return &self; }
	const LDKHTLCFailChannelUpdate* operator ->() const { return &self; }
};
class ChannelMessageHandler {
private:
	LDKChannelMessageHandler self;
public:
	ChannelMessageHandler(const ChannelMessageHandler&) = delete;
	ChannelMessageHandler(ChannelMessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelMessageHandler)); }
	ChannelMessageHandler(LDKChannelMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelMessageHandler)); }
	operator LDKChannelMessageHandler() && { LDKChannelMessageHandler res = self; memset(&self, 0, sizeof(LDKChannelMessageHandler)); return res; }
	~ChannelMessageHandler() { ChannelMessageHandler_free(self); }
	ChannelMessageHandler& operator=(ChannelMessageHandler&& o) { ChannelMessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(ChannelMessageHandler)); return *this; }
	LDKChannelMessageHandler* operator &() { return &self; }
	LDKChannelMessageHandler* operator ->() { return &self; }
	const LDKChannelMessageHandler* operator &() const { return &self; }
	const LDKChannelMessageHandler* operator ->() const { return &self; }
};
class RoutingMessageHandler {
private:
	LDKRoutingMessageHandler self;
public:
	RoutingMessageHandler(const RoutingMessageHandler&) = delete;
	RoutingMessageHandler(RoutingMessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(RoutingMessageHandler)); }
	RoutingMessageHandler(LDKRoutingMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRoutingMessageHandler)); }
	operator LDKRoutingMessageHandler() && { LDKRoutingMessageHandler res = self; memset(&self, 0, sizeof(LDKRoutingMessageHandler)); return res; }
	~RoutingMessageHandler() { RoutingMessageHandler_free(self); }
	RoutingMessageHandler& operator=(RoutingMessageHandler&& o) { RoutingMessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(RoutingMessageHandler)); return *this; }
	LDKRoutingMessageHandler* operator &() { return &self; }
	LDKRoutingMessageHandler* operator ->() { return &self; }
	const LDKRoutingMessageHandler* operator &() const { return &self; }
	const LDKRoutingMessageHandler* operator ->() const { return &self; }
};
class MessageHandler {
private:
	LDKMessageHandler self;
public:
	MessageHandler(const MessageHandler&) = delete;
	MessageHandler(MessageHandler&& o) : self(o.self) { memset(&o, 0, sizeof(MessageHandler)); }
	MessageHandler(LDKMessageHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKMessageHandler)); }
	operator LDKMessageHandler() && { LDKMessageHandler res = self; memset(&self, 0, sizeof(LDKMessageHandler)); return res; }
	~MessageHandler() { MessageHandler_free(self); }
	MessageHandler& operator=(MessageHandler&& o) { MessageHandler_free(self); self = o.self; memset(&o, 0, sizeof(MessageHandler)); return *this; }
	LDKMessageHandler* operator &() { return &self; }
	LDKMessageHandler* operator ->() { return &self; }
	const LDKMessageHandler* operator &() const { return &self; }
	const LDKMessageHandler* operator ->() const { return &self; }
};
class SocketDescriptor {
private:
	LDKSocketDescriptor self;
public:
	SocketDescriptor(const SocketDescriptor&) = delete;
	SocketDescriptor(SocketDescriptor&& o) : self(o.self) { memset(&o, 0, sizeof(SocketDescriptor)); }
	SocketDescriptor(LDKSocketDescriptor&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKSocketDescriptor)); }
	operator LDKSocketDescriptor() && { LDKSocketDescriptor res = self; memset(&self, 0, sizeof(LDKSocketDescriptor)); return res; }
	~SocketDescriptor() { SocketDescriptor_free(self); }
	SocketDescriptor& operator=(SocketDescriptor&& o) { SocketDescriptor_free(self); self = o.self; memset(&o, 0, sizeof(SocketDescriptor)); return *this; }
	LDKSocketDescriptor* operator &() { return &self; }
	LDKSocketDescriptor* operator ->() { return &self; }
	const LDKSocketDescriptor* operator &() const { return &self; }
	const LDKSocketDescriptor* operator ->() const { return &self; }
};
class PeerHandleError {
private:
	LDKPeerHandleError self;
public:
	PeerHandleError(const PeerHandleError&) = delete;
	PeerHandleError(PeerHandleError&& o) : self(o.self) { memset(&o, 0, sizeof(PeerHandleError)); }
	PeerHandleError(LDKPeerHandleError&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPeerHandleError)); }
	operator LDKPeerHandleError() && { LDKPeerHandleError res = self; memset(&self, 0, sizeof(LDKPeerHandleError)); return res; }
	~PeerHandleError() { PeerHandleError_free(self); }
	PeerHandleError& operator=(PeerHandleError&& o) { PeerHandleError_free(self); self = o.self; memset(&o, 0, sizeof(PeerHandleError)); return *this; }
	LDKPeerHandleError* operator &() { return &self; }
	LDKPeerHandleError* operator ->() { return &self; }
	const LDKPeerHandleError* operator &() const { return &self; }
	const LDKPeerHandleError* operator ->() const { return &self; }
};
class PeerManager {
private:
	LDKPeerManager self;
public:
	PeerManager(const PeerManager&) = delete;
	PeerManager(PeerManager&& o) : self(o.self) { memset(&o, 0, sizeof(PeerManager)); }
	PeerManager(LDKPeerManager&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKPeerManager)); }
	operator LDKPeerManager() && { LDKPeerManager res = self; memset(&self, 0, sizeof(LDKPeerManager)); return res; }
	~PeerManager() { PeerManager_free(self); }
	PeerManager& operator=(PeerManager&& o) { PeerManager_free(self); self = o.self; memset(&o, 0, sizeof(PeerManager)); return *this; }
	LDKPeerManager* operator &() { return &self; }
	LDKPeerManager* operator ->() { return &self; }
	const LDKPeerManager* operator &() const { return &self; }
	const LDKPeerManager* operator ->() const { return &self; }
};
class TxCreationKeys {
private:
	LDKTxCreationKeys self;
public:
	TxCreationKeys(const TxCreationKeys&) = delete;
	TxCreationKeys(TxCreationKeys&& o) : self(o.self) { memset(&o, 0, sizeof(TxCreationKeys)); }
	TxCreationKeys(LDKTxCreationKeys&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKTxCreationKeys)); }
	operator LDKTxCreationKeys() && { LDKTxCreationKeys res = self; memset(&self, 0, sizeof(LDKTxCreationKeys)); return res; }
	~TxCreationKeys() { TxCreationKeys_free(self); }
	TxCreationKeys& operator=(TxCreationKeys&& o) { TxCreationKeys_free(self); self = o.self; memset(&o, 0, sizeof(TxCreationKeys)); return *this; }
	LDKTxCreationKeys* operator &() { return &self; }
	LDKTxCreationKeys* operator ->() { return &self; }
	const LDKTxCreationKeys* operator &() const { return &self; }
	const LDKTxCreationKeys* operator ->() const { return &self; }
};
class ChannelPublicKeys {
private:
	LDKChannelPublicKeys self;
public:
	ChannelPublicKeys(const ChannelPublicKeys&) = delete;
	ChannelPublicKeys(ChannelPublicKeys&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelPublicKeys)); }
	ChannelPublicKeys(LDKChannelPublicKeys&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelPublicKeys)); }
	operator LDKChannelPublicKeys() && { LDKChannelPublicKeys res = self; memset(&self, 0, sizeof(LDKChannelPublicKeys)); return res; }
	~ChannelPublicKeys() { ChannelPublicKeys_free(self); }
	ChannelPublicKeys& operator=(ChannelPublicKeys&& o) { ChannelPublicKeys_free(self); self = o.self; memset(&o, 0, sizeof(ChannelPublicKeys)); return *this; }
	LDKChannelPublicKeys* operator &() { return &self; }
	LDKChannelPublicKeys* operator ->() { return &self; }
	const LDKChannelPublicKeys* operator &() const { return &self; }
	const LDKChannelPublicKeys* operator ->() const { return &self; }
};
class HTLCOutputInCommitment {
private:
	LDKHTLCOutputInCommitment self;
public:
	HTLCOutputInCommitment(const HTLCOutputInCommitment&) = delete;
	HTLCOutputInCommitment(HTLCOutputInCommitment&& o) : self(o.self) { memset(&o, 0, sizeof(HTLCOutputInCommitment)); }
	HTLCOutputInCommitment(LDKHTLCOutputInCommitment&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKHTLCOutputInCommitment)); }
	operator LDKHTLCOutputInCommitment() && { LDKHTLCOutputInCommitment res = self; memset(&self, 0, sizeof(LDKHTLCOutputInCommitment)); return res; }
	~HTLCOutputInCommitment() { HTLCOutputInCommitment_free(self); }
	HTLCOutputInCommitment& operator=(HTLCOutputInCommitment&& o) { HTLCOutputInCommitment_free(self); self = o.self; memset(&o, 0, sizeof(HTLCOutputInCommitment)); return *this; }
	LDKHTLCOutputInCommitment* operator &() { return &self; }
	LDKHTLCOutputInCommitment* operator ->() { return &self; }
	const LDKHTLCOutputInCommitment* operator &() const { return &self; }
	const LDKHTLCOutputInCommitment* operator ->() const { return &self; }
};
class ChannelTransactionParameters {
private:
	LDKChannelTransactionParameters self;
public:
	ChannelTransactionParameters(const ChannelTransactionParameters&) = delete;
	ChannelTransactionParameters(ChannelTransactionParameters&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelTransactionParameters)); }
	ChannelTransactionParameters(LDKChannelTransactionParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelTransactionParameters)); }
	operator LDKChannelTransactionParameters() && { LDKChannelTransactionParameters res = self; memset(&self, 0, sizeof(LDKChannelTransactionParameters)); return res; }
	~ChannelTransactionParameters() { ChannelTransactionParameters_free(self); }
	ChannelTransactionParameters& operator=(ChannelTransactionParameters&& o) { ChannelTransactionParameters_free(self); self = o.self; memset(&o, 0, sizeof(ChannelTransactionParameters)); return *this; }
	LDKChannelTransactionParameters* operator &() { return &self; }
	LDKChannelTransactionParameters* operator ->() { return &self; }
	const LDKChannelTransactionParameters* operator &() const { return &self; }
	const LDKChannelTransactionParameters* operator ->() const { return &self; }
};
class CounterpartyChannelTransactionParameters {
private:
	LDKCounterpartyChannelTransactionParameters self;
public:
	CounterpartyChannelTransactionParameters(const CounterpartyChannelTransactionParameters&) = delete;
	CounterpartyChannelTransactionParameters(CounterpartyChannelTransactionParameters&& o) : self(o.self) { memset(&o, 0, sizeof(CounterpartyChannelTransactionParameters)); }
	CounterpartyChannelTransactionParameters(LDKCounterpartyChannelTransactionParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCounterpartyChannelTransactionParameters)); }
	operator LDKCounterpartyChannelTransactionParameters() && { LDKCounterpartyChannelTransactionParameters res = self; memset(&self, 0, sizeof(LDKCounterpartyChannelTransactionParameters)); return res; }
	~CounterpartyChannelTransactionParameters() { CounterpartyChannelTransactionParameters_free(self); }
	CounterpartyChannelTransactionParameters& operator=(CounterpartyChannelTransactionParameters&& o) { CounterpartyChannelTransactionParameters_free(self); self = o.self; memset(&o, 0, sizeof(CounterpartyChannelTransactionParameters)); return *this; }
	LDKCounterpartyChannelTransactionParameters* operator &() { return &self; }
	LDKCounterpartyChannelTransactionParameters* operator ->() { return &self; }
	const LDKCounterpartyChannelTransactionParameters* operator &() const { return &self; }
	const LDKCounterpartyChannelTransactionParameters* operator ->() const { return &self; }
};
class DirectedChannelTransactionParameters {
private:
	LDKDirectedChannelTransactionParameters self;
public:
	DirectedChannelTransactionParameters(const DirectedChannelTransactionParameters&) = delete;
	DirectedChannelTransactionParameters(DirectedChannelTransactionParameters&& o) : self(o.self) { memset(&o, 0, sizeof(DirectedChannelTransactionParameters)); }
	DirectedChannelTransactionParameters(LDKDirectedChannelTransactionParameters&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDirectedChannelTransactionParameters)); }
	operator LDKDirectedChannelTransactionParameters() && { LDKDirectedChannelTransactionParameters res = self; memset(&self, 0, sizeof(LDKDirectedChannelTransactionParameters)); return res; }
	~DirectedChannelTransactionParameters() { DirectedChannelTransactionParameters_free(self); }
	DirectedChannelTransactionParameters& operator=(DirectedChannelTransactionParameters&& o) { DirectedChannelTransactionParameters_free(self); self = o.self; memset(&o, 0, sizeof(DirectedChannelTransactionParameters)); return *this; }
	LDKDirectedChannelTransactionParameters* operator &() { return &self; }
	LDKDirectedChannelTransactionParameters* operator ->() { return &self; }
	const LDKDirectedChannelTransactionParameters* operator &() const { return &self; }
	const LDKDirectedChannelTransactionParameters* operator ->() const { return &self; }
};
class HolderCommitmentTransaction {
private:
	LDKHolderCommitmentTransaction self;
public:
	HolderCommitmentTransaction(const HolderCommitmentTransaction&) = delete;
	HolderCommitmentTransaction(HolderCommitmentTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(HolderCommitmentTransaction)); }
	HolderCommitmentTransaction(LDKHolderCommitmentTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKHolderCommitmentTransaction)); }
	operator LDKHolderCommitmentTransaction() && { LDKHolderCommitmentTransaction res = self; memset(&self, 0, sizeof(LDKHolderCommitmentTransaction)); return res; }
	~HolderCommitmentTransaction() { HolderCommitmentTransaction_free(self); }
	HolderCommitmentTransaction& operator=(HolderCommitmentTransaction&& o) { HolderCommitmentTransaction_free(self); self = o.self; memset(&o, 0, sizeof(HolderCommitmentTransaction)); return *this; }
	LDKHolderCommitmentTransaction* operator &() { return &self; }
	LDKHolderCommitmentTransaction* operator ->() { return &self; }
	const LDKHolderCommitmentTransaction* operator &() const { return &self; }
	const LDKHolderCommitmentTransaction* operator ->() const { return &self; }
};
class BuiltCommitmentTransaction {
private:
	LDKBuiltCommitmentTransaction self;
public:
	BuiltCommitmentTransaction(const BuiltCommitmentTransaction&) = delete;
	BuiltCommitmentTransaction(BuiltCommitmentTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(BuiltCommitmentTransaction)); }
	BuiltCommitmentTransaction(LDKBuiltCommitmentTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKBuiltCommitmentTransaction)); }
	operator LDKBuiltCommitmentTransaction() && { LDKBuiltCommitmentTransaction res = self; memset(&self, 0, sizeof(LDKBuiltCommitmentTransaction)); return res; }
	~BuiltCommitmentTransaction() { BuiltCommitmentTransaction_free(self); }
	BuiltCommitmentTransaction& operator=(BuiltCommitmentTransaction&& o) { BuiltCommitmentTransaction_free(self); self = o.self; memset(&o, 0, sizeof(BuiltCommitmentTransaction)); return *this; }
	LDKBuiltCommitmentTransaction* operator &() { return &self; }
	LDKBuiltCommitmentTransaction* operator ->() { return &self; }
	const LDKBuiltCommitmentTransaction* operator &() const { return &self; }
	const LDKBuiltCommitmentTransaction* operator ->() const { return &self; }
};
class CommitmentTransaction {
private:
	LDKCommitmentTransaction self;
public:
	CommitmentTransaction(const CommitmentTransaction&) = delete;
	CommitmentTransaction(CommitmentTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(CommitmentTransaction)); }
	CommitmentTransaction(LDKCommitmentTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCommitmentTransaction)); }
	operator LDKCommitmentTransaction() && { LDKCommitmentTransaction res = self; memset(&self, 0, sizeof(LDKCommitmentTransaction)); return res; }
	~CommitmentTransaction() { CommitmentTransaction_free(self); }
	CommitmentTransaction& operator=(CommitmentTransaction&& o) { CommitmentTransaction_free(self); self = o.self; memset(&o, 0, sizeof(CommitmentTransaction)); return *this; }
	LDKCommitmentTransaction* operator &() { return &self; }
	LDKCommitmentTransaction* operator ->() { return &self; }
	const LDKCommitmentTransaction* operator &() const { return &self; }
	const LDKCommitmentTransaction* operator ->() const { return &self; }
};
class TrustedCommitmentTransaction {
private:
	LDKTrustedCommitmentTransaction self;
public:
	TrustedCommitmentTransaction(const TrustedCommitmentTransaction&) = delete;
	TrustedCommitmentTransaction(TrustedCommitmentTransaction&& o) : self(o.self) { memset(&o, 0, sizeof(TrustedCommitmentTransaction)); }
	TrustedCommitmentTransaction(LDKTrustedCommitmentTransaction&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKTrustedCommitmentTransaction)); }
	operator LDKTrustedCommitmentTransaction() && { LDKTrustedCommitmentTransaction res = self; memset(&self, 0, sizeof(LDKTrustedCommitmentTransaction)); return res; }
	~TrustedCommitmentTransaction() { TrustedCommitmentTransaction_free(self); }
	TrustedCommitmentTransaction& operator=(TrustedCommitmentTransaction&& o) { TrustedCommitmentTransaction_free(self); self = o.self; memset(&o, 0, sizeof(TrustedCommitmentTransaction)); return *this; }
	LDKTrustedCommitmentTransaction* operator &() { return &self; }
	LDKTrustedCommitmentTransaction* operator ->() { return &self; }
	const LDKTrustedCommitmentTransaction* operator &() const { return &self; }
	const LDKTrustedCommitmentTransaction* operator ->() const { return &self; }
};
class InitFeatures {
private:
	LDKInitFeatures self;
public:
	InitFeatures(const InitFeatures&) = delete;
	InitFeatures(InitFeatures&& o) : self(o.self) { memset(&o, 0, sizeof(InitFeatures)); }
	InitFeatures(LDKInitFeatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKInitFeatures)); }
	operator LDKInitFeatures() && { LDKInitFeatures res = self; memset(&self, 0, sizeof(LDKInitFeatures)); return res; }
	~InitFeatures() { InitFeatures_free(self); }
	InitFeatures& operator=(InitFeatures&& o) { InitFeatures_free(self); self = o.self; memset(&o, 0, sizeof(InitFeatures)); return *this; }
	LDKInitFeatures* operator &() { return &self; }
	LDKInitFeatures* operator ->() { return &self; }
	const LDKInitFeatures* operator &() const { return &self; }
	const LDKInitFeatures* operator ->() const { return &self; }
};
class NodeFeatures {
private:
	LDKNodeFeatures self;
public:
	NodeFeatures(const NodeFeatures&) = delete;
	NodeFeatures(NodeFeatures&& o) : self(o.self) { memset(&o, 0, sizeof(NodeFeatures)); }
	NodeFeatures(LDKNodeFeatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeFeatures)); }
	operator LDKNodeFeatures() && { LDKNodeFeatures res = self; memset(&self, 0, sizeof(LDKNodeFeatures)); return res; }
	~NodeFeatures() { NodeFeatures_free(self); }
	NodeFeatures& operator=(NodeFeatures&& o) { NodeFeatures_free(self); self = o.self; memset(&o, 0, sizeof(NodeFeatures)); return *this; }
	LDKNodeFeatures* operator &() { return &self; }
	LDKNodeFeatures* operator ->() { return &self; }
	const LDKNodeFeatures* operator &() const { return &self; }
	const LDKNodeFeatures* operator ->() const { return &self; }
};
class ChannelFeatures {
private:
	LDKChannelFeatures self;
public:
	ChannelFeatures(const ChannelFeatures&) = delete;
	ChannelFeatures(ChannelFeatures&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelFeatures)); }
	ChannelFeatures(LDKChannelFeatures&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelFeatures)); }
	operator LDKChannelFeatures() && { LDKChannelFeatures res = self; memset(&self, 0, sizeof(LDKChannelFeatures)); return res; }
	~ChannelFeatures() { ChannelFeatures_free(self); }
	ChannelFeatures& operator=(ChannelFeatures&& o) { ChannelFeatures_free(self); self = o.self; memset(&o, 0, sizeof(ChannelFeatures)); return *this; }
	LDKChannelFeatures* operator &() { return &self; }
	LDKChannelFeatures* operator ->() { return &self; }
	const LDKChannelFeatures* operator &() const { return &self; }
	const LDKChannelFeatures* operator ->() const { return &self; }
};
class RouteHop {
private:
	LDKRouteHop self;
public:
	RouteHop(const RouteHop&) = delete;
	RouteHop(RouteHop&& o) : self(o.self) { memset(&o, 0, sizeof(RouteHop)); }
	RouteHop(LDKRouteHop&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRouteHop)); }
	operator LDKRouteHop() && { LDKRouteHop res = self; memset(&self, 0, sizeof(LDKRouteHop)); return res; }
	~RouteHop() { RouteHop_free(self); }
	RouteHop& operator=(RouteHop&& o) { RouteHop_free(self); self = o.self; memset(&o, 0, sizeof(RouteHop)); return *this; }
	LDKRouteHop* operator &() { return &self; }
	LDKRouteHop* operator ->() { return &self; }
	const LDKRouteHop* operator &() const { return &self; }
	const LDKRouteHop* operator ->() const { return &self; }
};
class Route {
private:
	LDKRoute self;
public:
	Route(const Route&) = delete;
	Route(Route&& o) : self(o.self) { memset(&o, 0, sizeof(Route)); }
	Route(LDKRoute&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRoute)); }
	operator LDKRoute() && { LDKRoute res = self; memset(&self, 0, sizeof(LDKRoute)); return res; }
	~Route() { Route_free(self); }
	Route& operator=(Route&& o) { Route_free(self); self = o.self; memset(&o, 0, sizeof(Route)); return *this; }
	LDKRoute* operator &() { return &self; }
	LDKRoute* operator ->() { return &self; }
	const LDKRoute* operator &() const { return &self; }
	const LDKRoute* operator ->() const { return &self; }
};
class RouteHint {
private:
	LDKRouteHint self;
public:
	RouteHint(const RouteHint&) = delete;
	RouteHint(RouteHint&& o) : self(o.self) { memset(&o, 0, sizeof(RouteHint)); }
	RouteHint(LDKRouteHint&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRouteHint)); }
	operator LDKRouteHint() && { LDKRouteHint res = self; memset(&self, 0, sizeof(LDKRouteHint)); return res; }
	~RouteHint() { RouteHint_free(self); }
	RouteHint& operator=(RouteHint&& o) { RouteHint_free(self); self = o.self; memset(&o, 0, sizeof(RouteHint)); return *this; }
	LDKRouteHint* operator &() { return &self; }
	LDKRouteHint* operator ->() { return &self; }
	const LDKRouteHint* operator &() const { return &self; }
	const LDKRouteHint* operator ->() const { return &self; }
};
class NetworkGraph {
private:
	LDKNetworkGraph self;
public:
	NetworkGraph(const NetworkGraph&) = delete;
	NetworkGraph(NetworkGraph&& o) : self(o.self) { memset(&o, 0, sizeof(NetworkGraph)); }
	NetworkGraph(LDKNetworkGraph&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNetworkGraph)); }
	operator LDKNetworkGraph() && { LDKNetworkGraph res = self; memset(&self, 0, sizeof(LDKNetworkGraph)); return res; }
	~NetworkGraph() { NetworkGraph_free(self); }
	NetworkGraph& operator=(NetworkGraph&& o) { NetworkGraph_free(self); self = o.self; memset(&o, 0, sizeof(NetworkGraph)); return *this; }
	LDKNetworkGraph* operator &() { return &self; }
	LDKNetworkGraph* operator ->() { return &self; }
	const LDKNetworkGraph* operator &() const { return &self; }
	const LDKNetworkGraph* operator ->() const { return &self; }
};
class LockedNetworkGraph {
private:
	LDKLockedNetworkGraph self;
public:
	LockedNetworkGraph(const LockedNetworkGraph&) = delete;
	LockedNetworkGraph(LockedNetworkGraph&& o) : self(o.self) { memset(&o, 0, sizeof(LockedNetworkGraph)); }
	LockedNetworkGraph(LDKLockedNetworkGraph&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKLockedNetworkGraph)); }
	operator LDKLockedNetworkGraph() && { LDKLockedNetworkGraph res = self; memset(&self, 0, sizeof(LDKLockedNetworkGraph)); return res; }
	~LockedNetworkGraph() { LockedNetworkGraph_free(self); }
	LockedNetworkGraph& operator=(LockedNetworkGraph&& o) { LockedNetworkGraph_free(self); self = o.self; memset(&o, 0, sizeof(LockedNetworkGraph)); return *this; }
	LDKLockedNetworkGraph* operator &() { return &self; }
	LDKLockedNetworkGraph* operator ->() { return &self; }
	const LDKLockedNetworkGraph* operator &() const { return &self; }
	const LDKLockedNetworkGraph* operator ->() const { return &self; }
};
class NetGraphMsgHandler {
private:
	LDKNetGraphMsgHandler self;
public:
	NetGraphMsgHandler(const NetGraphMsgHandler&) = delete;
	NetGraphMsgHandler(NetGraphMsgHandler&& o) : self(o.self) { memset(&o, 0, sizeof(NetGraphMsgHandler)); }
	NetGraphMsgHandler(LDKNetGraphMsgHandler&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNetGraphMsgHandler)); }
	operator LDKNetGraphMsgHandler() && { LDKNetGraphMsgHandler res = self; memset(&self, 0, sizeof(LDKNetGraphMsgHandler)); return res; }
	~NetGraphMsgHandler() { NetGraphMsgHandler_free(self); }
	NetGraphMsgHandler& operator=(NetGraphMsgHandler&& o) { NetGraphMsgHandler_free(self); self = o.self; memset(&o, 0, sizeof(NetGraphMsgHandler)); return *this; }
	LDKNetGraphMsgHandler* operator &() { return &self; }
	LDKNetGraphMsgHandler* operator ->() { return &self; }
	const LDKNetGraphMsgHandler* operator &() const { return &self; }
	const LDKNetGraphMsgHandler* operator ->() const { return &self; }
};
class DirectionalChannelInfo {
private:
	LDKDirectionalChannelInfo self;
public:
	DirectionalChannelInfo(const DirectionalChannelInfo&) = delete;
	DirectionalChannelInfo(DirectionalChannelInfo&& o) : self(o.self) { memset(&o, 0, sizeof(DirectionalChannelInfo)); }
	DirectionalChannelInfo(LDKDirectionalChannelInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKDirectionalChannelInfo)); }
	operator LDKDirectionalChannelInfo() && { LDKDirectionalChannelInfo res = self; memset(&self, 0, sizeof(LDKDirectionalChannelInfo)); return res; }
	~DirectionalChannelInfo() { DirectionalChannelInfo_free(self); }
	DirectionalChannelInfo& operator=(DirectionalChannelInfo&& o) { DirectionalChannelInfo_free(self); self = o.self; memset(&o, 0, sizeof(DirectionalChannelInfo)); return *this; }
	LDKDirectionalChannelInfo* operator &() { return &self; }
	LDKDirectionalChannelInfo* operator ->() { return &self; }
	const LDKDirectionalChannelInfo* operator &() const { return &self; }
	const LDKDirectionalChannelInfo* operator ->() const { return &self; }
};
class ChannelInfo {
private:
	LDKChannelInfo self;
public:
	ChannelInfo(const ChannelInfo&) = delete;
	ChannelInfo(ChannelInfo&& o) : self(o.self) { memset(&o, 0, sizeof(ChannelInfo)); }
	ChannelInfo(LDKChannelInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKChannelInfo)); }
	operator LDKChannelInfo() && { LDKChannelInfo res = self; memset(&self, 0, sizeof(LDKChannelInfo)); return res; }
	~ChannelInfo() { ChannelInfo_free(self); }
	ChannelInfo& operator=(ChannelInfo&& o) { ChannelInfo_free(self); self = o.self; memset(&o, 0, sizeof(ChannelInfo)); return *this; }
	LDKChannelInfo* operator &() { return &self; }
	LDKChannelInfo* operator ->() { return &self; }
	const LDKChannelInfo* operator &() const { return &self; }
	const LDKChannelInfo* operator ->() const { return &self; }
};
class RoutingFees {
private:
	LDKRoutingFees self;
public:
	RoutingFees(const RoutingFees&) = delete;
	RoutingFees(RoutingFees&& o) : self(o.self) { memset(&o, 0, sizeof(RoutingFees)); }
	RoutingFees(LDKRoutingFees&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKRoutingFees)); }
	operator LDKRoutingFees() && { LDKRoutingFees res = self; memset(&self, 0, sizeof(LDKRoutingFees)); return res; }
	~RoutingFees() { RoutingFees_free(self); }
	RoutingFees& operator=(RoutingFees&& o) { RoutingFees_free(self); self = o.self; memset(&o, 0, sizeof(RoutingFees)); return *this; }
	LDKRoutingFees* operator &() { return &self; }
	LDKRoutingFees* operator ->() { return &self; }
	const LDKRoutingFees* operator &() const { return &self; }
	const LDKRoutingFees* operator ->() const { return &self; }
};
class NodeAnnouncementInfo {
private:
	LDKNodeAnnouncementInfo self;
public:
	NodeAnnouncementInfo(const NodeAnnouncementInfo&) = delete;
	NodeAnnouncementInfo(NodeAnnouncementInfo&& o) : self(o.self) { memset(&o, 0, sizeof(NodeAnnouncementInfo)); }
	NodeAnnouncementInfo(LDKNodeAnnouncementInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeAnnouncementInfo)); }
	operator LDKNodeAnnouncementInfo() && { LDKNodeAnnouncementInfo res = self; memset(&self, 0, sizeof(LDKNodeAnnouncementInfo)); return res; }
	~NodeAnnouncementInfo() { NodeAnnouncementInfo_free(self); }
	NodeAnnouncementInfo& operator=(NodeAnnouncementInfo&& o) { NodeAnnouncementInfo_free(self); self = o.self; memset(&o, 0, sizeof(NodeAnnouncementInfo)); return *this; }
	LDKNodeAnnouncementInfo* operator &() { return &self; }
	LDKNodeAnnouncementInfo* operator ->() { return &self; }
	const LDKNodeAnnouncementInfo* operator &() const { return &self; }
	const LDKNodeAnnouncementInfo* operator ->() const { return &self; }
};
class NodeInfo {
private:
	LDKNodeInfo self;
public:
	NodeInfo(const NodeInfo&) = delete;
	NodeInfo(NodeInfo&& o) : self(o.self) { memset(&o, 0, sizeof(NodeInfo)); }
	NodeInfo(LDKNodeInfo&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKNodeInfo)); }
	operator LDKNodeInfo() && { LDKNodeInfo res = self; memset(&self, 0, sizeof(LDKNodeInfo)); return res; }
	~NodeInfo() { NodeInfo_free(self); }
	NodeInfo& operator=(NodeInfo&& o) { NodeInfo_free(self); self = o.self; memset(&o, 0, sizeof(NodeInfo)); return *this; }
	LDKNodeInfo* operator &() { return &self; }
	LDKNodeInfo* operator ->() { return &self; }
	const LDKNodeInfo* operator &() const { return &self; }
	const LDKNodeInfo* operator ->() const { return &self; }
};
class CVec_SpendableOutputDescriptorZ {
private:
	LDKCVec_SpendableOutputDescriptorZ self;
public:
	CVec_SpendableOutputDescriptorZ(const CVec_SpendableOutputDescriptorZ&) = delete;
	CVec_SpendableOutputDescriptorZ(CVec_SpendableOutputDescriptorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_SpendableOutputDescriptorZ)); }
	CVec_SpendableOutputDescriptorZ(LDKCVec_SpendableOutputDescriptorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_SpendableOutputDescriptorZ)); }
	operator LDKCVec_SpendableOutputDescriptorZ() && { LDKCVec_SpendableOutputDescriptorZ res = self; memset(&self, 0, sizeof(LDKCVec_SpendableOutputDescriptorZ)); return res; }
	~CVec_SpendableOutputDescriptorZ() { CVec_SpendableOutputDescriptorZ_free(self); }
	CVec_SpendableOutputDescriptorZ& operator=(CVec_SpendableOutputDescriptorZ&& o) { CVec_SpendableOutputDescriptorZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_SpendableOutputDescriptorZ)); return *this; }
	LDKCVec_SpendableOutputDescriptorZ* operator &() { return &self; }
	LDKCVec_SpendableOutputDescriptorZ* operator ->() { return &self; }
	const LDKCVec_SpendableOutputDescriptorZ* operator &() const { return &self; }
	const LDKCVec_SpendableOutputDescriptorZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
private:
	LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ self;
public:
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ(const CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ&) = delete;
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ(CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ)); }
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ(LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ)); }
	operator LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ() && { LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ)); return res; }
	~CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ() { CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_free(self); }
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ& operator=(CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ&& o) { CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ)); return *this; }
	LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ* operator &() { return &self; }
	LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
private:
	LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ self;
public:
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ(const CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ&) = delete;
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ(CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ)); }
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ(LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ)); }
	operator LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ() && { LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ)); return res; }
	~CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ() { CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_free(self); }
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ& operator=(CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ&& o) { CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ)); return *this; }
	LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
private:
	LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ self;
public:
	CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ(const CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ&) = delete;
	CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ(CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ)); }
	CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ(LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ)); }
	operator LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ() && { LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ res = self; memset(&self, 0, sizeof(LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ)); return res; }
	~CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ() { CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ_free(self); }
	CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ& operator=(CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ&& o) { CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ)); return *this; }
	LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ* operator &() { return &self; }
	LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ* operator ->() { return &self; }
	const LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ* operator &() const { return &self; }
	const LDKCVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ* operator ->() const { return &self; }
};
class C2Tuple_BlockHashChannelManagerZ {
private:
	LDKC2Tuple_BlockHashChannelManagerZ self;
public:
	C2Tuple_BlockHashChannelManagerZ(const C2Tuple_BlockHashChannelManagerZ&) = delete;
	C2Tuple_BlockHashChannelManagerZ(C2Tuple_BlockHashChannelManagerZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_BlockHashChannelManagerZ)); }
	C2Tuple_BlockHashChannelManagerZ(LDKC2Tuple_BlockHashChannelManagerZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_BlockHashChannelManagerZ)); }
	operator LDKC2Tuple_BlockHashChannelManagerZ() && { LDKC2Tuple_BlockHashChannelManagerZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_BlockHashChannelManagerZ)); return res; }
	~C2Tuple_BlockHashChannelManagerZ() { C2Tuple_BlockHashChannelManagerZ_free(self); }
	C2Tuple_BlockHashChannelManagerZ& operator=(C2Tuple_BlockHashChannelManagerZ&& o) { C2Tuple_BlockHashChannelManagerZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_BlockHashChannelManagerZ)); return *this; }
	LDKC2Tuple_BlockHashChannelManagerZ* operator &() { return &self; }
	LDKC2Tuple_BlockHashChannelManagerZ* operator ->() { return &self; }
	const LDKC2Tuple_BlockHashChannelManagerZ* operator &() const { return &self; }
	const LDKC2Tuple_BlockHashChannelManagerZ* operator ->() const { return &self; }
};
class CVec_C2Tuple_u32TxOutZZ {
private:
	LDKCVec_C2Tuple_u32TxOutZZ self;
public:
	CVec_C2Tuple_u32TxOutZZ(const CVec_C2Tuple_u32TxOutZZ&) = delete;
	CVec_C2Tuple_u32TxOutZZ(CVec_C2Tuple_u32TxOutZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C2Tuple_u32TxOutZZ)); }
	CVec_C2Tuple_u32TxOutZZ(LDKCVec_C2Tuple_u32TxOutZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C2Tuple_u32TxOutZZ)); }
	operator LDKCVec_C2Tuple_u32TxOutZZ() && { LDKCVec_C2Tuple_u32TxOutZZ res = self; memset(&self, 0, sizeof(LDKCVec_C2Tuple_u32TxOutZZ)); return res; }
	~CVec_C2Tuple_u32TxOutZZ() { CVec_C2Tuple_u32TxOutZZ_free(self); }
	CVec_C2Tuple_u32TxOutZZ& operator=(CVec_C2Tuple_u32TxOutZZ&& o) { CVec_C2Tuple_u32TxOutZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C2Tuple_u32TxOutZZ)); return *this; }
	LDKCVec_C2Tuple_u32TxOutZZ* operator &() { return &self; }
	LDKCVec_C2Tuple_u32TxOutZZ* operator ->() { return &self; }
	const LDKCVec_C2Tuple_u32TxOutZZ* operator &() const { return &self; }
	const LDKCVec_C2Tuple_u32TxOutZZ* operator ->() const { return &self; }
};
class CVec_SignatureZ {
private:
	LDKCVec_SignatureZ self;
public:
	CVec_SignatureZ(const CVec_SignatureZ&) = delete;
	CVec_SignatureZ(CVec_SignatureZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_SignatureZ)); }
	CVec_SignatureZ(LDKCVec_SignatureZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_SignatureZ)); }
	operator LDKCVec_SignatureZ() && { LDKCVec_SignatureZ res = self; memset(&self, 0, sizeof(LDKCVec_SignatureZ)); return res; }
	~CVec_SignatureZ() { CVec_SignatureZ_free(self); }
	CVec_SignatureZ& operator=(CVec_SignatureZ&& o) { CVec_SignatureZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_SignatureZ)); return *this; }
	LDKCVec_SignatureZ* operator &() { return &self; }
	LDKCVec_SignatureZ* operator ->() { return &self; }
	const LDKCVec_SignatureZ* operator &() const { return &self; }
	const LDKCVec_SignatureZ* operator ->() const { return &self; }
};
class C2Tuple_SignatureCVec_SignatureZZ {
private:
	LDKC2Tuple_SignatureCVec_SignatureZZ self;
public:
	C2Tuple_SignatureCVec_SignatureZZ(const C2Tuple_SignatureCVec_SignatureZZ&) = delete;
	C2Tuple_SignatureCVec_SignatureZZ(C2Tuple_SignatureCVec_SignatureZZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_SignatureCVec_SignatureZZ)); }
	C2Tuple_SignatureCVec_SignatureZZ(LDKC2Tuple_SignatureCVec_SignatureZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_SignatureCVec_SignatureZZ)); }
	operator LDKC2Tuple_SignatureCVec_SignatureZZ() && { LDKC2Tuple_SignatureCVec_SignatureZZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_SignatureCVec_SignatureZZ)); return res; }
	~C2Tuple_SignatureCVec_SignatureZZ() { C2Tuple_SignatureCVec_SignatureZZ_free(self); }
	C2Tuple_SignatureCVec_SignatureZZ& operator=(C2Tuple_SignatureCVec_SignatureZZ&& o) { C2Tuple_SignatureCVec_SignatureZZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_SignatureCVec_SignatureZZ)); return *this; }
	LDKC2Tuple_SignatureCVec_SignatureZZ* operator &() { return &self; }
	LDKC2Tuple_SignatureCVec_SignatureZZ* operator ->() { return &self; }
	const LDKC2Tuple_SignatureCVec_SignatureZZ* operator &() const { return &self; }
	const LDKC2Tuple_SignatureCVec_SignatureZZ* operator ->() const { return &self; }
};
class CVec_u64Z {
private:
	LDKCVec_u64Z self;
public:
	CVec_u64Z(const CVec_u64Z&) = delete;
	CVec_u64Z(CVec_u64Z&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_u64Z)); }
	CVec_u64Z(LDKCVec_u64Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_u64Z)); }
	operator LDKCVec_u64Z() && { LDKCVec_u64Z res = self; memset(&self, 0, sizeof(LDKCVec_u64Z)); return res; }
	~CVec_u64Z() { CVec_u64Z_free(self); }
	CVec_u64Z& operator=(CVec_u64Z&& o) { CVec_u64Z_free(self); self = o.self; memset(&o, 0, sizeof(CVec_u64Z)); return *this; }
	LDKCVec_u64Z* operator &() { return &self; }
	LDKCVec_u64Z* operator ->() { return &self; }
	const LDKCVec_u64Z* operator &() const { return &self; }
	const LDKCVec_u64Z* operator ->() const { return &self; }
};
class CResult_GossipTimestampFilterDecodeErrorZ {
private:
	LDKCResult_GossipTimestampFilterDecodeErrorZ self;
public:
	CResult_GossipTimestampFilterDecodeErrorZ(const CResult_GossipTimestampFilterDecodeErrorZ&) = delete;
	CResult_GossipTimestampFilterDecodeErrorZ(CResult_GossipTimestampFilterDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_GossipTimestampFilterDecodeErrorZ)); }
	CResult_GossipTimestampFilterDecodeErrorZ(LDKCResult_GossipTimestampFilterDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_GossipTimestampFilterDecodeErrorZ)); }
	operator LDKCResult_GossipTimestampFilterDecodeErrorZ() && { LDKCResult_GossipTimestampFilterDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_GossipTimestampFilterDecodeErrorZ)); return res; }
	~CResult_GossipTimestampFilterDecodeErrorZ() { CResult_GossipTimestampFilterDecodeErrorZ_free(self); }
	CResult_GossipTimestampFilterDecodeErrorZ& operator=(CResult_GossipTimestampFilterDecodeErrorZ&& o) { CResult_GossipTimestampFilterDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_GossipTimestampFilterDecodeErrorZ)); return *this; }
	LDKCResult_GossipTimestampFilterDecodeErrorZ* operator &() { return &self; }
	LDKCResult_GossipTimestampFilterDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_GossipTimestampFilterDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_GossipTimestampFilterDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ChannelMonitorUpdateDecodeErrorZ {
private:
	LDKCResult_ChannelMonitorUpdateDecodeErrorZ self;
public:
	CResult_ChannelMonitorUpdateDecodeErrorZ(const CResult_ChannelMonitorUpdateDecodeErrorZ&) = delete;
	CResult_ChannelMonitorUpdateDecodeErrorZ(CResult_ChannelMonitorUpdateDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelMonitorUpdateDecodeErrorZ)); }
	CResult_ChannelMonitorUpdateDecodeErrorZ(LDKCResult_ChannelMonitorUpdateDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelMonitorUpdateDecodeErrorZ)); }
	operator LDKCResult_ChannelMonitorUpdateDecodeErrorZ() && { LDKCResult_ChannelMonitorUpdateDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelMonitorUpdateDecodeErrorZ)); return res; }
	~CResult_ChannelMonitorUpdateDecodeErrorZ() { CResult_ChannelMonitorUpdateDecodeErrorZ_free(self); }
	CResult_ChannelMonitorUpdateDecodeErrorZ& operator=(CResult_ChannelMonitorUpdateDecodeErrorZ&& o) { CResult_ChannelMonitorUpdateDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelMonitorUpdateDecodeErrorZ)); return *this; }
	LDKCResult_ChannelMonitorUpdateDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelMonitorUpdateDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelMonitorUpdateDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelMonitorUpdateDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ReplyChannelRangeDecodeErrorZ {
private:
	LDKCResult_ReplyChannelRangeDecodeErrorZ self;
public:
	CResult_ReplyChannelRangeDecodeErrorZ(const CResult_ReplyChannelRangeDecodeErrorZ&) = delete;
	CResult_ReplyChannelRangeDecodeErrorZ(CResult_ReplyChannelRangeDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ReplyChannelRangeDecodeErrorZ)); }
	CResult_ReplyChannelRangeDecodeErrorZ(LDKCResult_ReplyChannelRangeDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ReplyChannelRangeDecodeErrorZ)); }
	operator LDKCResult_ReplyChannelRangeDecodeErrorZ() && { LDKCResult_ReplyChannelRangeDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ReplyChannelRangeDecodeErrorZ)); return res; }
	~CResult_ReplyChannelRangeDecodeErrorZ() { CResult_ReplyChannelRangeDecodeErrorZ_free(self); }
	CResult_ReplyChannelRangeDecodeErrorZ& operator=(CResult_ReplyChannelRangeDecodeErrorZ&& o) { CResult_ReplyChannelRangeDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ReplyChannelRangeDecodeErrorZ)); return *this; }
	LDKCResult_ReplyChannelRangeDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ReplyChannelRangeDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ReplyChannelRangeDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ReplyChannelRangeDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_CVec_u8ZPeerHandleErrorZ {
private:
	LDKCResult_CVec_u8ZPeerHandleErrorZ self;
public:
	CResult_CVec_u8ZPeerHandleErrorZ(const CResult_CVec_u8ZPeerHandleErrorZ&) = delete;
	CResult_CVec_u8ZPeerHandleErrorZ(CResult_CVec_u8ZPeerHandleErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CVec_u8ZPeerHandleErrorZ)); }
	CResult_CVec_u8ZPeerHandleErrorZ(LDKCResult_CVec_u8ZPeerHandleErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CVec_u8ZPeerHandleErrorZ)); }
	operator LDKCResult_CVec_u8ZPeerHandleErrorZ() && { LDKCResult_CVec_u8ZPeerHandleErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_CVec_u8ZPeerHandleErrorZ)); return res; }
	~CResult_CVec_u8ZPeerHandleErrorZ() { CResult_CVec_u8ZPeerHandleErrorZ_free(self); }
	CResult_CVec_u8ZPeerHandleErrorZ& operator=(CResult_CVec_u8ZPeerHandleErrorZ&& o) { CResult_CVec_u8ZPeerHandleErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CVec_u8ZPeerHandleErrorZ)); return *this; }
	LDKCResult_CVec_u8ZPeerHandleErrorZ* operator &() { return &self; }
	LDKCResult_CVec_u8ZPeerHandleErrorZ* operator ->() { return &self; }
	const LDKCResult_CVec_u8ZPeerHandleErrorZ* operator &() const { return &self; }
	const LDKCResult_CVec_u8ZPeerHandleErrorZ* operator ->() const { return &self; }
};
class CResult_TxOutAccessErrorZ {
private:
	LDKCResult_TxOutAccessErrorZ self;
public:
	CResult_TxOutAccessErrorZ(const CResult_TxOutAccessErrorZ&) = delete;
	CResult_TxOutAccessErrorZ(CResult_TxOutAccessErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_TxOutAccessErrorZ)); }
	CResult_TxOutAccessErrorZ(LDKCResult_TxOutAccessErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_TxOutAccessErrorZ)); }
	operator LDKCResult_TxOutAccessErrorZ() && { LDKCResult_TxOutAccessErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_TxOutAccessErrorZ)); return res; }
	~CResult_TxOutAccessErrorZ() { CResult_TxOutAccessErrorZ_free(self); }
	CResult_TxOutAccessErrorZ& operator=(CResult_TxOutAccessErrorZ&& o) { CResult_TxOutAccessErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_TxOutAccessErrorZ)); return *this; }
	LDKCResult_TxOutAccessErrorZ* operator &() { return &self; }
	LDKCResult_TxOutAccessErrorZ* operator ->() { return &self; }
	const LDKCResult_TxOutAccessErrorZ* operator &() const { return &self; }
	const LDKCResult_TxOutAccessErrorZ* operator ->() const { return &self; }
};
class CResult_UnsignedNodeAnnouncementDecodeErrorZ {
private:
	LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ self;
public:
	CResult_UnsignedNodeAnnouncementDecodeErrorZ(const CResult_UnsignedNodeAnnouncementDecodeErrorZ&) = delete;
	CResult_UnsignedNodeAnnouncementDecodeErrorZ(CResult_UnsignedNodeAnnouncementDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UnsignedNodeAnnouncementDecodeErrorZ)); }
	CResult_UnsignedNodeAnnouncementDecodeErrorZ(LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ)); }
	operator LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ() && { LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ)); return res; }
	~CResult_UnsignedNodeAnnouncementDecodeErrorZ() { CResult_UnsignedNodeAnnouncementDecodeErrorZ_free(self); }
	CResult_UnsignedNodeAnnouncementDecodeErrorZ& operator=(CResult_UnsignedNodeAnnouncementDecodeErrorZ&& o) { CResult_UnsignedNodeAnnouncementDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UnsignedNodeAnnouncementDecodeErrorZ)); return *this; }
	LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UnsignedNodeAnnouncementDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_TxCreationKeysSecpErrorZ {
private:
	LDKCResult_TxCreationKeysSecpErrorZ self;
public:
	CResult_TxCreationKeysSecpErrorZ(const CResult_TxCreationKeysSecpErrorZ&) = delete;
	CResult_TxCreationKeysSecpErrorZ(CResult_TxCreationKeysSecpErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_TxCreationKeysSecpErrorZ)); }
	CResult_TxCreationKeysSecpErrorZ(LDKCResult_TxCreationKeysSecpErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_TxCreationKeysSecpErrorZ)); }
	operator LDKCResult_TxCreationKeysSecpErrorZ() && { LDKCResult_TxCreationKeysSecpErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_TxCreationKeysSecpErrorZ)); return res; }
	~CResult_TxCreationKeysSecpErrorZ() { CResult_TxCreationKeysSecpErrorZ_free(self); }
	CResult_TxCreationKeysSecpErrorZ& operator=(CResult_TxCreationKeysSecpErrorZ&& o) { CResult_TxCreationKeysSecpErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_TxCreationKeysSecpErrorZ)); return *this; }
	LDKCResult_TxCreationKeysSecpErrorZ* operator &() { return &self; }
	LDKCResult_TxCreationKeysSecpErrorZ* operator ->() { return &self; }
	const LDKCResult_TxCreationKeysSecpErrorZ* operator &() const { return &self; }
	const LDKCResult_TxCreationKeysSecpErrorZ* operator ->() const { return &self; }
};
class CVec_RouteHintZ {
private:
	LDKCVec_RouteHintZ self;
public:
	CVec_RouteHintZ(const CVec_RouteHintZ&) = delete;
	CVec_RouteHintZ(CVec_RouteHintZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_RouteHintZ)); }
	CVec_RouteHintZ(LDKCVec_RouteHintZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_RouteHintZ)); }
	operator LDKCVec_RouteHintZ() && { LDKCVec_RouteHintZ res = self; memset(&self, 0, sizeof(LDKCVec_RouteHintZ)); return res; }
	~CVec_RouteHintZ() { CVec_RouteHintZ_free(self); }
	CVec_RouteHintZ& operator=(CVec_RouteHintZ&& o) { CVec_RouteHintZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_RouteHintZ)); return *this; }
	LDKCVec_RouteHintZ* operator &() { return &self; }
	LDKCVec_RouteHintZ* operator ->() { return &self; }
	const LDKCVec_RouteHintZ* operator &() const { return &self; }
	const LDKCVec_RouteHintZ* operator ->() const { return &self; }
};
class CResult_ChannelReestablishDecodeErrorZ {
private:
	LDKCResult_ChannelReestablishDecodeErrorZ self;
public:
	CResult_ChannelReestablishDecodeErrorZ(const CResult_ChannelReestablishDecodeErrorZ&) = delete;
	CResult_ChannelReestablishDecodeErrorZ(CResult_ChannelReestablishDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChannelReestablishDecodeErrorZ)); }
	CResult_ChannelReestablishDecodeErrorZ(LDKCResult_ChannelReestablishDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChannelReestablishDecodeErrorZ)); }
	operator LDKCResult_ChannelReestablishDecodeErrorZ() && { LDKCResult_ChannelReestablishDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChannelReestablishDecodeErrorZ)); return res; }
	~CResult_ChannelReestablishDecodeErrorZ() { CResult_ChannelReestablishDecodeErrorZ_free(self); }
	CResult_ChannelReestablishDecodeErrorZ& operator=(CResult_ChannelReestablishDecodeErrorZ&& o) { CResult_ChannelReestablishDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChannelReestablishDecodeErrorZ)); return *this; }
	LDKCResult_ChannelReestablishDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChannelReestablishDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChannelReestablishDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChannelReestablishDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_CVec_RouteHopZZ {
private:
	LDKCVec_CVec_RouteHopZZ self;
public:
	CVec_CVec_RouteHopZZ(const CVec_CVec_RouteHopZZ&) = delete;
	CVec_CVec_RouteHopZZ(CVec_CVec_RouteHopZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_CVec_RouteHopZZ)); }
	CVec_CVec_RouteHopZZ(LDKCVec_CVec_RouteHopZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_CVec_RouteHopZZ)); }
	operator LDKCVec_CVec_RouteHopZZ() && { LDKCVec_CVec_RouteHopZZ res = self; memset(&self, 0, sizeof(LDKCVec_CVec_RouteHopZZ)); return res; }
	~CVec_CVec_RouteHopZZ() { CVec_CVec_RouteHopZZ_free(self); }
	CVec_CVec_RouteHopZZ& operator=(CVec_CVec_RouteHopZZ&& o) { CVec_CVec_RouteHopZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_CVec_RouteHopZZ)); return *this; }
	LDKCVec_CVec_RouteHopZZ* operator &() { return &self; }
	LDKCVec_CVec_RouteHopZZ* operator ->() { return &self; }
	const LDKCVec_CVec_RouteHopZZ* operator &() const { return &self; }
	const LDKCVec_CVec_RouteHopZZ* operator ->() const { return &self; }
};
class CVec_UpdateAddHTLCZ {
private:
	LDKCVec_UpdateAddHTLCZ self;
public:
	CVec_UpdateAddHTLCZ(const CVec_UpdateAddHTLCZ&) = delete;
	CVec_UpdateAddHTLCZ(CVec_UpdateAddHTLCZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_UpdateAddHTLCZ)); }
	CVec_UpdateAddHTLCZ(LDKCVec_UpdateAddHTLCZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_UpdateAddHTLCZ)); }
	operator LDKCVec_UpdateAddHTLCZ() && { LDKCVec_UpdateAddHTLCZ res = self; memset(&self, 0, sizeof(LDKCVec_UpdateAddHTLCZ)); return res; }
	~CVec_UpdateAddHTLCZ() { CVec_UpdateAddHTLCZ_free(self); }
	CVec_UpdateAddHTLCZ& operator=(CVec_UpdateAddHTLCZ&& o) { CVec_UpdateAddHTLCZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_UpdateAddHTLCZ)); return *this; }
	LDKCVec_UpdateAddHTLCZ* operator &() { return &self; }
	LDKCVec_UpdateAddHTLCZ* operator ->() { return &self; }
	const LDKCVec_UpdateAddHTLCZ* operator &() const { return &self; }
	const LDKCVec_UpdateAddHTLCZ* operator ->() const { return &self; }
};
class CResult_NoneLightningErrorZ {
private:
	LDKCResult_NoneLightningErrorZ self;
public:
	CResult_NoneLightningErrorZ(const CResult_NoneLightningErrorZ&) = delete;
	CResult_NoneLightningErrorZ(CResult_NoneLightningErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneLightningErrorZ)); }
	CResult_NoneLightningErrorZ(LDKCResult_NoneLightningErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneLightningErrorZ)); }
	operator LDKCResult_NoneLightningErrorZ() && { LDKCResult_NoneLightningErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneLightningErrorZ)); return res; }
	~CResult_NoneLightningErrorZ() { CResult_NoneLightningErrorZ_free(self); }
	CResult_NoneLightningErrorZ& operator=(CResult_NoneLightningErrorZ&& o) { CResult_NoneLightningErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneLightningErrorZ)); return *this; }
	LDKCResult_NoneLightningErrorZ* operator &() { return &self; }
	LDKCResult_NoneLightningErrorZ* operator ->() { return &self; }
	const LDKCResult_NoneLightningErrorZ* operator &() const { return &self; }
	const LDKCResult_NoneLightningErrorZ* operator ->() const { return &self; }
};
class CResult_NonePeerHandleErrorZ {
private:
	LDKCResult_NonePeerHandleErrorZ self;
public:
	CResult_NonePeerHandleErrorZ(const CResult_NonePeerHandleErrorZ&) = delete;
	CResult_NonePeerHandleErrorZ(CResult_NonePeerHandleErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NonePeerHandleErrorZ)); }
	CResult_NonePeerHandleErrorZ(LDKCResult_NonePeerHandleErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NonePeerHandleErrorZ)); }
	operator LDKCResult_NonePeerHandleErrorZ() && { LDKCResult_NonePeerHandleErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NonePeerHandleErrorZ)); return res; }
	~CResult_NonePeerHandleErrorZ() { CResult_NonePeerHandleErrorZ_free(self); }
	CResult_NonePeerHandleErrorZ& operator=(CResult_NonePeerHandleErrorZ&& o) { CResult_NonePeerHandleErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NonePeerHandleErrorZ)); return *this; }
	LDKCResult_NonePeerHandleErrorZ* operator &() { return &self; }
	LDKCResult_NonePeerHandleErrorZ* operator ->() { return &self; }
	const LDKCResult_NonePeerHandleErrorZ* operator &() const { return &self; }
	const LDKCResult_NonePeerHandleErrorZ* operator ->() const { return &self; }
};
class CResult_TrustedCommitmentTransactionNoneZ {
private:
	LDKCResult_TrustedCommitmentTransactionNoneZ self;
public:
	CResult_TrustedCommitmentTransactionNoneZ(const CResult_TrustedCommitmentTransactionNoneZ&) = delete;
	CResult_TrustedCommitmentTransactionNoneZ(CResult_TrustedCommitmentTransactionNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_TrustedCommitmentTransactionNoneZ)); }
	CResult_TrustedCommitmentTransactionNoneZ(LDKCResult_TrustedCommitmentTransactionNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_TrustedCommitmentTransactionNoneZ)); }
	operator LDKCResult_TrustedCommitmentTransactionNoneZ() && { LDKCResult_TrustedCommitmentTransactionNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_TrustedCommitmentTransactionNoneZ)); return res; }
	~CResult_TrustedCommitmentTransactionNoneZ() { CResult_TrustedCommitmentTransactionNoneZ_free(self); }
	CResult_TrustedCommitmentTransactionNoneZ& operator=(CResult_TrustedCommitmentTransactionNoneZ&& o) { CResult_TrustedCommitmentTransactionNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_TrustedCommitmentTransactionNoneZ)); return *this; }
	LDKCResult_TrustedCommitmentTransactionNoneZ* operator &() { return &self; }
	LDKCResult_TrustedCommitmentTransactionNoneZ* operator ->() { return &self; }
	const LDKCResult_TrustedCommitmentTransactionNoneZ* operator &() const { return &self; }
	const LDKCResult_TrustedCommitmentTransactionNoneZ* operator ->() const { return &self; }
};
class CResult_CVec_SignatureZNoneZ {
private:
	LDKCResult_CVec_SignatureZNoneZ self;
public:
	CResult_CVec_SignatureZNoneZ(const CResult_CVec_SignatureZNoneZ&) = delete;
	CResult_CVec_SignatureZNoneZ(CResult_CVec_SignatureZNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CVec_SignatureZNoneZ)); }
	CResult_CVec_SignatureZNoneZ(LDKCResult_CVec_SignatureZNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CVec_SignatureZNoneZ)); }
	operator LDKCResult_CVec_SignatureZNoneZ() && { LDKCResult_CVec_SignatureZNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_CVec_SignatureZNoneZ)); return res; }
	~CResult_CVec_SignatureZNoneZ() { CResult_CVec_SignatureZNoneZ_free(self); }
	CResult_CVec_SignatureZNoneZ& operator=(CResult_CVec_SignatureZNoneZ&& o) { CResult_CVec_SignatureZNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CVec_SignatureZNoneZ)); return *this; }
	LDKCResult_CVec_SignatureZNoneZ* operator &() { return &self; }
	LDKCResult_CVec_SignatureZNoneZ* operator ->() { return &self; }
	const LDKCResult_CVec_SignatureZNoneZ* operator &() const { return &self; }
	const LDKCResult_CVec_SignatureZNoneZ* operator ->() const { return &self; }
};
class CResult_PingDecodeErrorZ {
private:
	LDKCResult_PingDecodeErrorZ self;
public:
	CResult_PingDecodeErrorZ(const CResult_PingDecodeErrorZ&) = delete;
	CResult_PingDecodeErrorZ(CResult_PingDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PingDecodeErrorZ)); }
	CResult_PingDecodeErrorZ(LDKCResult_PingDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PingDecodeErrorZ)); }
	operator LDKCResult_PingDecodeErrorZ() && { LDKCResult_PingDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PingDecodeErrorZ)); return res; }
	~CResult_PingDecodeErrorZ() { CResult_PingDecodeErrorZ_free(self); }
	CResult_PingDecodeErrorZ& operator=(CResult_PingDecodeErrorZ&& o) { CResult_PingDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PingDecodeErrorZ)); return *this; }
	LDKCResult_PingDecodeErrorZ* operator &() { return &self; }
	LDKCResult_PingDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_PingDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_PingDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_RoutingFeesDecodeErrorZ {
private:
	LDKCResult_RoutingFeesDecodeErrorZ self;
public:
	CResult_RoutingFeesDecodeErrorZ(const CResult_RoutingFeesDecodeErrorZ&) = delete;
	CResult_RoutingFeesDecodeErrorZ(CResult_RoutingFeesDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RoutingFeesDecodeErrorZ)); }
	CResult_RoutingFeesDecodeErrorZ(LDKCResult_RoutingFeesDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RoutingFeesDecodeErrorZ)); }
	operator LDKCResult_RoutingFeesDecodeErrorZ() && { LDKCResult_RoutingFeesDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RoutingFeesDecodeErrorZ)); return res; }
	~CResult_RoutingFeesDecodeErrorZ() { CResult_RoutingFeesDecodeErrorZ_free(self); }
	CResult_RoutingFeesDecodeErrorZ& operator=(CResult_RoutingFeesDecodeErrorZ&& o) { CResult_RoutingFeesDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RoutingFeesDecodeErrorZ)); return *this; }
	LDKCResult_RoutingFeesDecodeErrorZ* operator &() { return &self; }
	LDKCResult_RoutingFeesDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_RoutingFeesDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_RoutingFeesDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ErrorMessageDecodeErrorZ {
private:
	LDKCResult_ErrorMessageDecodeErrorZ self;
public:
	CResult_ErrorMessageDecodeErrorZ(const CResult_ErrorMessageDecodeErrorZ&) = delete;
	CResult_ErrorMessageDecodeErrorZ(CResult_ErrorMessageDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ErrorMessageDecodeErrorZ)); }
	CResult_ErrorMessageDecodeErrorZ(LDKCResult_ErrorMessageDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ErrorMessageDecodeErrorZ)); }
	operator LDKCResult_ErrorMessageDecodeErrorZ() && { LDKCResult_ErrorMessageDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ErrorMessageDecodeErrorZ)); return res; }
	~CResult_ErrorMessageDecodeErrorZ() { CResult_ErrorMessageDecodeErrorZ_free(self); }
	CResult_ErrorMessageDecodeErrorZ& operator=(CResult_ErrorMessageDecodeErrorZ&& o) { CResult_ErrorMessageDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ErrorMessageDecodeErrorZ)); return *this; }
	LDKCResult_ErrorMessageDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ErrorMessageDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ErrorMessageDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ErrorMessageDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_QueryShortChannelIdsDecodeErrorZ {
private:
	LDKCResult_QueryShortChannelIdsDecodeErrorZ self;
public:
	CResult_QueryShortChannelIdsDecodeErrorZ(const CResult_QueryShortChannelIdsDecodeErrorZ&) = delete;
	CResult_QueryShortChannelIdsDecodeErrorZ(CResult_QueryShortChannelIdsDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_QueryShortChannelIdsDecodeErrorZ)); }
	CResult_QueryShortChannelIdsDecodeErrorZ(LDKCResult_QueryShortChannelIdsDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_QueryShortChannelIdsDecodeErrorZ)); }
	operator LDKCResult_QueryShortChannelIdsDecodeErrorZ() && { LDKCResult_QueryShortChannelIdsDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_QueryShortChannelIdsDecodeErrorZ)); return res; }
	~CResult_QueryShortChannelIdsDecodeErrorZ() { CResult_QueryShortChannelIdsDecodeErrorZ_free(self); }
	CResult_QueryShortChannelIdsDecodeErrorZ& operator=(CResult_QueryShortChannelIdsDecodeErrorZ&& o) { CResult_QueryShortChannelIdsDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_QueryShortChannelIdsDecodeErrorZ)); return *this; }
	LDKCResult_QueryShortChannelIdsDecodeErrorZ* operator &() { return &self; }
	LDKCResult_QueryShortChannelIdsDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_QueryShortChannelIdsDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_QueryShortChannelIdsDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_NoneAPIErrorZ {
private:
	LDKCResult_NoneAPIErrorZ self;
public:
	CResult_NoneAPIErrorZ(const CResult_NoneAPIErrorZ&) = delete;
	CResult_NoneAPIErrorZ(CResult_NoneAPIErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneAPIErrorZ)); }
	CResult_NoneAPIErrorZ(LDKCResult_NoneAPIErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneAPIErrorZ)); }
	operator LDKCResult_NoneAPIErrorZ() && { LDKCResult_NoneAPIErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneAPIErrorZ)); return res; }
	~CResult_NoneAPIErrorZ() { CResult_NoneAPIErrorZ_free(self); }
	CResult_NoneAPIErrorZ& operator=(CResult_NoneAPIErrorZ&& o) { CResult_NoneAPIErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneAPIErrorZ)); return *this; }
	LDKCResult_NoneAPIErrorZ* operator &() { return &self; }
	LDKCResult_NoneAPIErrorZ* operator ->() { return &self; }
	const LDKCResult_NoneAPIErrorZ* operator &() const { return &self; }
	const LDKCResult_NoneAPIErrorZ* operator ->() const { return &self; }
};
class CResult_QueryChannelRangeDecodeErrorZ {
private:
	LDKCResult_QueryChannelRangeDecodeErrorZ self;
public:
	CResult_QueryChannelRangeDecodeErrorZ(const CResult_QueryChannelRangeDecodeErrorZ&) = delete;
	CResult_QueryChannelRangeDecodeErrorZ(CResult_QueryChannelRangeDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_QueryChannelRangeDecodeErrorZ)); }
	CResult_QueryChannelRangeDecodeErrorZ(LDKCResult_QueryChannelRangeDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_QueryChannelRangeDecodeErrorZ)); }
	operator LDKCResult_QueryChannelRangeDecodeErrorZ() && { LDKCResult_QueryChannelRangeDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_QueryChannelRangeDecodeErrorZ)); return res; }
	~CResult_QueryChannelRangeDecodeErrorZ() { CResult_QueryChannelRangeDecodeErrorZ_free(self); }
	CResult_QueryChannelRangeDecodeErrorZ& operator=(CResult_QueryChannelRangeDecodeErrorZ&& o) { CResult_QueryChannelRangeDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_QueryChannelRangeDecodeErrorZ)); return *this; }
	LDKCResult_QueryChannelRangeDecodeErrorZ* operator &() { return &self; }
	LDKCResult_QueryChannelRangeDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_QueryChannelRangeDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_QueryChannelRangeDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_NetAddressZ {
private:
	LDKCVec_NetAddressZ self;
public:
	CVec_NetAddressZ(const CVec_NetAddressZ&) = delete;
	CVec_NetAddressZ(CVec_NetAddressZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_NetAddressZ)); }
	CVec_NetAddressZ(LDKCVec_NetAddressZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_NetAddressZ)); }
	operator LDKCVec_NetAddressZ() && { LDKCVec_NetAddressZ res = self; memset(&self, 0, sizeof(LDKCVec_NetAddressZ)); return res; }
	~CVec_NetAddressZ() { CVec_NetAddressZ_free(self); }
	CVec_NetAddressZ& operator=(CVec_NetAddressZ&& o) { CVec_NetAddressZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_NetAddressZ)); return *this; }
	LDKCVec_NetAddressZ* operator &() { return &self; }
	LDKCVec_NetAddressZ* operator ->() { return &self; }
	const LDKCVec_NetAddressZ* operator &() const { return &self; }
	const LDKCVec_NetAddressZ* operator ->() const { return &self; }
};
class C2Tuple_usizeTransactionZ {
private:
	LDKC2Tuple_usizeTransactionZ self;
public:
	C2Tuple_usizeTransactionZ(const C2Tuple_usizeTransactionZ&) = delete;
	C2Tuple_usizeTransactionZ(C2Tuple_usizeTransactionZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_usizeTransactionZ)); }
	C2Tuple_usizeTransactionZ(LDKC2Tuple_usizeTransactionZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_usizeTransactionZ)); }
	operator LDKC2Tuple_usizeTransactionZ() && { LDKC2Tuple_usizeTransactionZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_usizeTransactionZ)); return res; }
	~C2Tuple_usizeTransactionZ() { C2Tuple_usizeTransactionZ_free(self); }
	C2Tuple_usizeTransactionZ& operator=(C2Tuple_usizeTransactionZ&& o) { C2Tuple_usizeTransactionZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_usizeTransactionZ)); return *this; }
	LDKC2Tuple_usizeTransactionZ* operator &() { return &self; }
	LDKC2Tuple_usizeTransactionZ* operator ->() { return &self; }
	const LDKC2Tuple_usizeTransactionZ* operator &() const { return &self; }
	const LDKC2Tuple_usizeTransactionZ* operator ->() const { return &self; }
};
class CVec_C2Tuple_usizeTransactionZZ {
private:
	LDKCVec_C2Tuple_usizeTransactionZZ self;
public:
	CVec_C2Tuple_usizeTransactionZZ(const CVec_C2Tuple_usizeTransactionZZ&) = delete;
	CVec_C2Tuple_usizeTransactionZZ(CVec_C2Tuple_usizeTransactionZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C2Tuple_usizeTransactionZZ)); }
	CVec_C2Tuple_usizeTransactionZZ(LDKCVec_C2Tuple_usizeTransactionZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C2Tuple_usizeTransactionZZ)); }
	operator LDKCVec_C2Tuple_usizeTransactionZZ() && { LDKCVec_C2Tuple_usizeTransactionZZ res = self; memset(&self, 0, sizeof(LDKCVec_C2Tuple_usizeTransactionZZ)); return res; }
	~CVec_C2Tuple_usizeTransactionZZ() { CVec_C2Tuple_usizeTransactionZZ_free(self); }
	CVec_C2Tuple_usizeTransactionZZ& operator=(CVec_C2Tuple_usizeTransactionZZ&& o) { CVec_C2Tuple_usizeTransactionZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C2Tuple_usizeTransactionZZ)); return *this; }
	LDKCVec_C2Tuple_usizeTransactionZZ* operator &() { return &self; }
	LDKCVec_C2Tuple_usizeTransactionZZ* operator ->() { return &self; }
	const LDKCVec_C2Tuple_usizeTransactionZZ* operator &() const { return &self; }
	const LDKCVec_C2Tuple_usizeTransactionZZ* operator ->() const { return &self; }
};
class CVec_TransactionZ {
private:
	LDKCVec_TransactionZ self;
public:
	CVec_TransactionZ(const CVec_TransactionZ&) = delete;
	CVec_TransactionZ(CVec_TransactionZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_TransactionZ)); }
	CVec_TransactionZ(LDKCVec_TransactionZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_TransactionZ)); }
	operator LDKCVec_TransactionZ() && { LDKCVec_TransactionZ res = self; memset(&self, 0, sizeof(LDKCVec_TransactionZ)); return res; }
	~CVec_TransactionZ() { CVec_TransactionZ_free(self); }
	CVec_TransactionZ& operator=(CVec_TransactionZ&& o) { CVec_TransactionZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_TransactionZ)); return *this; }
	LDKCVec_TransactionZ* operator &() { return &self; }
	LDKCVec_TransactionZ* operator ->() { return &self; }
	const LDKCVec_TransactionZ* operator &() const { return &self; }
	const LDKCVec_TransactionZ* operator ->() const { return &self; }
};
class CVec_ChannelMonitorZ {
private:
	LDKCVec_ChannelMonitorZ self;
public:
	CVec_ChannelMonitorZ(const CVec_ChannelMonitorZ&) = delete;
	CVec_ChannelMonitorZ(CVec_ChannelMonitorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_ChannelMonitorZ)); }
	CVec_ChannelMonitorZ(LDKCVec_ChannelMonitorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_ChannelMonitorZ)); }
	operator LDKCVec_ChannelMonitorZ() && { LDKCVec_ChannelMonitorZ res = self; memset(&self, 0, sizeof(LDKCVec_ChannelMonitorZ)); return res; }
	~CVec_ChannelMonitorZ() { CVec_ChannelMonitorZ_free(self); }
	CVec_ChannelMonitorZ& operator=(CVec_ChannelMonitorZ&& o) { CVec_ChannelMonitorZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_ChannelMonitorZ)); return *this; }
	LDKCVec_ChannelMonitorZ* operator &() { return &self; }
	LDKCVec_ChannelMonitorZ* operator ->() { return &self; }
	const LDKCVec_ChannelMonitorZ* operator &() const { return &self; }
	const LDKCVec_ChannelMonitorZ* operator ->() const { return &self; }
};
class CVec_PublicKeyZ {
private:
	LDKCVec_PublicKeyZ self;
public:
	CVec_PublicKeyZ(const CVec_PublicKeyZ&) = delete;
	CVec_PublicKeyZ(CVec_PublicKeyZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_PublicKeyZ)); }
	CVec_PublicKeyZ(LDKCVec_PublicKeyZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_PublicKeyZ)); }
	operator LDKCVec_PublicKeyZ() && { LDKCVec_PublicKeyZ res = self; memset(&self, 0, sizeof(LDKCVec_PublicKeyZ)); return res; }
	~CVec_PublicKeyZ() { CVec_PublicKeyZ_free(self); }
	CVec_PublicKeyZ& operator=(CVec_PublicKeyZ&& o) { CVec_PublicKeyZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_PublicKeyZ)); return *this; }
	LDKCVec_PublicKeyZ* operator &() { return &self; }
	LDKCVec_PublicKeyZ* operator ->() { return &self; }
	const LDKCVec_PublicKeyZ* operator &() const { return &self; }
	const LDKCVec_PublicKeyZ* operator ->() const { return &self; }
};
class C2Tuple_u64u64Z {
private:
	LDKC2Tuple_u64u64Z self;
public:
	C2Tuple_u64u64Z(const C2Tuple_u64u64Z&) = delete;
	C2Tuple_u64u64Z(C2Tuple_u64u64Z&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_u64u64Z)); }
	C2Tuple_u64u64Z(LDKC2Tuple_u64u64Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_u64u64Z)); }
	operator LDKC2Tuple_u64u64Z() && { LDKC2Tuple_u64u64Z res = self; memset(&self, 0, sizeof(LDKC2Tuple_u64u64Z)); return res; }
	~C2Tuple_u64u64Z() { C2Tuple_u64u64Z_free(self); }
	C2Tuple_u64u64Z& operator=(C2Tuple_u64u64Z&& o) { C2Tuple_u64u64Z_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_u64u64Z)); return *this; }
	LDKC2Tuple_u64u64Z* operator &() { return &self; }
	LDKC2Tuple_u64u64Z* operator ->() { return &self; }
	const LDKC2Tuple_u64u64Z* operator &() const { return &self; }
	const LDKC2Tuple_u64u64Z* operator ->() const { return &self; }
};
class C2Tuple_u32TxOutZ {
private:
	LDKC2Tuple_u32TxOutZ self;
public:
	C2Tuple_u32TxOutZ(const C2Tuple_u32TxOutZ&) = delete;
	C2Tuple_u32TxOutZ(C2Tuple_u32TxOutZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_u32TxOutZ)); }
	C2Tuple_u32TxOutZ(LDKC2Tuple_u32TxOutZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_u32TxOutZ)); }
	operator LDKC2Tuple_u32TxOutZ() && { LDKC2Tuple_u32TxOutZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_u32TxOutZ)); return res; }
	~C2Tuple_u32TxOutZ() { C2Tuple_u32TxOutZ_free(self); }
	C2Tuple_u32TxOutZ& operator=(C2Tuple_u32TxOutZ&& o) { C2Tuple_u32TxOutZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_u32TxOutZ)); return *this; }
	LDKC2Tuple_u32TxOutZ* operator &() { return &self; }
	LDKC2Tuple_u32TxOutZ* operator ->() { return &self; }
	const LDKC2Tuple_u32TxOutZ* operator &() const { return &self; }
	const LDKC2Tuple_u32TxOutZ* operator ->() const { return &self; }
};
class CResult_boolLightningErrorZ {
private:
	LDKCResult_boolLightningErrorZ self;
public:
	CResult_boolLightningErrorZ(const CResult_boolLightningErrorZ&) = delete;
	CResult_boolLightningErrorZ(CResult_boolLightningErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_boolLightningErrorZ)); }
	CResult_boolLightningErrorZ(LDKCResult_boolLightningErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_boolLightningErrorZ)); }
	operator LDKCResult_boolLightningErrorZ() && { LDKCResult_boolLightningErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_boolLightningErrorZ)); return res; }
	~CResult_boolLightningErrorZ() { CResult_boolLightningErrorZ_free(self); }
	CResult_boolLightningErrorZ& operator=(CResult_boolLightningErrorZ&& o) { CResult_boolLightningErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_boolLightningErrorZ)); return *this; }
	LDKCResult_boolLightningErrorZ* operator &() { return &self; }
	LDKCResult_boolLightningErrorZ* operator ->() { return &self; }
	const LDKCResult_boolLightningErrorZ* operator &() const { return &self; }
	const LDKCResult_boolLightningErrorZ* operator ->() const { return &self; }
};
class C2Tuple_BlockHashChannelMonitorZ {
private:
	LDKC2Tuple_BlockHashChannelMonitorZ self;
public:
	C2Tuple_BlockHashChannelMonitorZ(const C2Tuple_BlockHashChannelMonitorZ&) = delete;
	C2Tuple_BlockHashChannelMonitorZ(C2Tuple_BlockHashChannelMonitorZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_BlockHashChannelMonitorZ)); }
	C2Tuple_BlockHashChannelMonitorZ(LDKC2Tuple_BlockHashChannelMonitorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_BlockHashChannelMonitorZ)); }
	operator LDKC2Tuple_BlockHashChannelMonitorZ() && { LDKC2Tuple_BlockHashChannelMonitorZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_BlockHashChannelMonitorZ)); return res; }
	~C2Tuple_BlockHashChannelMonitorZ() { C2Tuple_BlockHashChannelMonitorZ_free(self); }
	C2Tuple_BlockHashChannelMonitorZ& operator=(C2Tuple_BlockHashChannelMonitorZ&& o) { C2Tuple_BlockHashChannelMonitorZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_BlockHashChannelMonitorZ)); return *this; }
	LDKC2Tuple_BlockHashChannelMonitorZ* operator &() { return &self; }
	LDKC2Tuple_BlockHashChannelMonitorZ* operator ->() { return &self; }
	const LDKC2Tuple_BlockHashChannelMonitorZ* operator &() const { return &self; }
	const LDKC2Tuple_BlockHashChannelMonitorZ* operator ->() const { return &self; }
};
class CResult_SecretKeySecpErrorZ {
private:
	LDKCResult_SecretKeySecpErrorZ self;
public:
	CResult_SecretKeySecpErrorZ(const CResult_SecretKeySecpErrorZ&) = delete;
	CResult_SecretKeySecpErrorZ(CResult_SecretKeySecpErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SecretKeySecpErrorZ)); }
	CResult_SecretKeySecpErrorZ(LDKCResult_SecretKeySecpErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SecretKeySecpErrorZ)); }
	operator LDKCResult_SecretKeySecpErrorZ() && { LDKCResult_SecretKeySecpErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_SecretKeySecpErrorZ)); return res; }
	~CResult_SecretKeySecpErrorZ() { CResult_SecretKeySecpErrorZ_free(self); }
	CResult_SecretKeySecpErrorZ& operator=(CResult_SecretKeySecpErrorZ&& o) { CResult_SecretKeySecpErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SecretKeySecpErrorZ)); return *this; }
	LDKCResult_SecretKeySecpErrorZ* operator &() { return &self; }
	LDKCResult_SecretKeySecpErrorZ* operator ->() { return &self; }
	const LDKCResult_SecretKeySecpErrorZ* operator &() const { return &self; }
	const LDKCResult_SecretKeySecpErrorZ* operator ->() const { return &self; }
};
class CResult_NodeAnnouncementInfoDecodeErrorZ {
private:
	LDKCResult_NodeAnnouncementInfoDecodeErrorZ self;
public:
	CResult_NodeAnnouncementInfoDecodeErrorZ(const CResult_NodeAnnouncementInfoDecodeErrorZ&) = delete;
	CResult_NodeAnnouncementInfoDecodeErrorZ(CResult_NodeAnnouncementInfoDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NodeAnnouncementInfoDecodeErrorZ)); }
	CResult_NodeAnnouncementInfoDecodeErrorZ(LDKCResult_NodeAnnouncementInfoDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NodeAnnouncementInfoDecodeErrorZ)); }
	operator LDKCResult_NodeAnnouncementInfoDecodeErrorZ() && { LDKCResult_NodeAnnouncementInfoDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NodeAnnouncementInfoDecodeErrorZ)); return res; }
	~CResult_NodeAnnouncementInfoDecodeErrorZ() { CResult_NodeAnnouncementInfoDecodeErrorZ_free(self); }
	CResult_NodeAnnouncementInfoDecodeErrorZ& operator=(CResult_NodeAnnouncementInfoDecodeErrorZ&& o) { CResult_NodeAnnouncementInfoDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NodeAnnouncementInfoDecodeErrorZ)); return *this; }
	LDKCResult_NodeAnnouncementInfoDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NodeAnnouncementInfoDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NodeAnnouncementInfoDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NodeAnnouncementInfoDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_SpendableOutputDescriptorDecodeErrorZ {
private:
	LDKCResult_SpendableOutputDescriptorDecodeErrorZ self;
public:
	CResult_SpendableOutputDescriptorDecodeErrorZ(const CResult_SpendableOutputDescriptorDecodeErrorZ&) = delete;
	CResult_SpendableOutputDescriptorDecodeErrorZ(CResult_SpendableOutputDescriptorDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SpendableOutputDescriptorDecodeErrorZ)); }
	CResult_SpendableOutputDescriptorDecodeErrorZ(LDKCResult_SpendableOutputDescriptorDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SpendableOutputDescriptorDecodeErrorZ)); }
	operator LDKCResult_SpendableOutputDescriptorDecodeErrorZ() && { LDKCResult_SpendableOutputDescriptorDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_SpendableOutputDescriptorDecodeErrorZ)); return res; }
	~CResult_SpendableOutputDescriptorDecodeErrorZ() { CResult_SpendableOutputDescriptorDecodeErrorZ_free(self); }
	CResult_SpendableOutputDescriptorDecodeErrorZ& operator=(CResult_SpendableOutputDescriptorDecodeErrorZ&& o) { CResult_SpendableOutputDescriptorDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SpendableOutputDescriptorDecodeErrorZ)); return *this; }
	LDKCResult_SpendableOutputDescriptorDecodeErrorZ* operator &() { return &self; }
	LDKCResult_SpendableOutputDescriptorDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_SpendableOutputDescriptorDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_SpendableOutputDescriptorDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_NetAddressu8Z {
private:
	LDKCResult_NetAddressu8Z self;
public:
	CResult_NetAddressu8Z(const CResult_NetAddressu8Z&) = delete;
	CResult_NetAddressu8Z(CResult_NetAddressu8Z&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NetAddressu8Z)); }
	CResult_NetAddressu8Z(LDKCResult_NetAddressu8Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NetAddressu8Z)); }
	operator LDKCResult_NetAddressu8Z() && { LDKCResult_NetAddressu8Z res = self; memset(&self, 0, sizeof(LDKCResult_NetAddressu8Z)); return res; }
	~CResult_NetAddressu8Z() { CResult_NetAddressu8Z_free(self); }
	CResult_NetAddressu8Z& operator=(CResult_NetAddressu8Z&& o) { CResult_NetAddressu8Z_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NetAddressu8Z)); return *this; }
	LDKCResult_NetAddressu8Z* operator &() { return &self; }
	LDKCResult_NetAddressu8Z* operator ->() { return &self; }
	const LDKCResult_NetAddressu8Z* operator &() const { return &self; }
	const LDKCResult_NetAddressu8Z* operator ->() const { return &self; }
};
class CVec_UpdateFailMalformedHTLCZ {
private:
	LDKCVec_UpdateFailMalformedHTLCZ self;
public:
	CVec_UpdateFailMalformedHTLCZ(const CVec_UpdateFailMalformedHTLCZ&) = delete;
	CVec_UpdateFailMalformedHTLCZ(CVec_UpdateFailMalformedHTLCZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_UpdateFailMalformedHTLCZ)); }
	CVec_UpdateFailMalformedHTLCZ(LDKCVec_UpdateFailMalformedHTLCZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_UpdateFailMalformedHTLCZ)); }
	operator LDKCVec_UpdateFailMalformedHTLCZ() && { LDKCVec_UpdateFailMalformedHTLCZ res = self; memset(&self, 0, sizeof(LDKCVec_UpdateFailMalformedHTLCZ)); return res; }
	~CVec_UpdateFailMalformedHTLCZ() { CVec_UpdateFailMalformedHTLCZ_free(self); }
	CVec_UpdateFailMalformedHTLCZ& operator=(CVec_UpdateFailMalformedHTLCZ&& o) { CVec_UpdateFailMalformedHTLCZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_UpdateFailMalformedHTLCZ)); return *this; }
	LDKCVec_UpdateFailMalformedHTLCZ* operator &() { return &self; }
	LDKCVec_UpdateFailMalformedHTLCZ* operator ->() { return &self; }
	const LDKCVec_UpdateFailMalformedHTLCZ* operator &() const { return &self; }
	const LDKCVec_UpdateFailMalformedHTLCZ* operator ->() const { return &self; }
};
class CResult_UnsignedChannelUpdateDecodeErrorZ {
private:
	LDKCResult_UnsignedChannelUpdateDecodeErrorZ self;
public:
	CResult_UnsignedChannelUpdateDecodeErrorZ(const CResult_UnsignedChannelUpdateDecodeErrorZ&) = delete;
	CResult_UnsignedChannelUpdateDecodeErrorZ(CResult_UnsignedChannelUpdateDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UnsignedChannelUpdateDecodeErrorZ)); }
	CResult_UnsignedChannelUpdateDecodeErrorZ(LDKCResult_UnsignedChannelUpdateDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UnsignedChannelUpdateDecodeErrorZ)); }
	operator LDKCResult_UnsignedChannelUpdateDecodeErrorZ() && { LDKCResult_UnsignedChannelUpdateDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UnsignedChannelUpdateDecodeErrorZ)); return res; }
	~CResult_UnsignedChannelUpdateDecodeErrorZ() { CResult_UnsignedChannelUpdateDecodeErrorZ_free(self); }
	CResult_UnsignedChannelUpdateDecodeErrorZ& operator=(CResult_UnsignedChannelUpdateDecodeErrorZ&& o) { CResult_UnsignedChannelUpdateDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UnsignedChannelUpdateDecodeErrorZ)); return *this; }
	LDKCResult_UnsignedChannelUpdateDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UnsignedChannelUpdateDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UnsignedChannelUpdateDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UnsignedChannelUpdateDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_EventZ {
private:
	LDKCVec_EventZ self;
public:
	CVec_EventZ(const CVec_EventZ&) = delete;
	CVec_EventZ(CVec_EventZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_EventZ)); }
	CVec_EventZ(LDKCVec_EventZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_EventZ)); }
	operator LDKCVec_EventZ() && { LDKCVec_EventZ res = self; memset(&self, 0, sizeof(LDKCVec_EventZ)); return res; }
	~CVec_EventZ() { CVec_EventZ_free(self); }
	CVec_EventZ& operator=(CVec_EventZ&& o) { CVec_EventZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_EventZ)); return *this; }
	LDKCVec_EventZ* operator &() { return &self; }
	LDKCVec_EventZ* operator ->() { return &self; }
	const LDKCVec_EventZ* operator &() const { return &self; }
	const LDKCVec_EventZ* operator ->() const { return &self; }
};
class CResult_NetworkGraphDecodeErrorZ {
private:
	LDKCResult_NetworkGraphDecodeErrorZ self;
public:
	CResult_NetworkGraphDecodeErrorZ(const CResult_NetworkGraphDecodeErrorZ&) = delete;
	CResult_NetworkGraphDecodeErrorZ(CResult_NetworkGraphDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NetworkGraphDecodeErrorZ)); }
	CResult_NetworkGraphDecodeErrorZ(LDKCResult_NetworkGraphDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NetworkGraphDecodeErrorZ)); }
	operator LDKCResult_NetworkGraphDecodeErrorZ() && { LDKCResult_NetworkGraphDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NetworkGraphDecodeErrorZ)); return res; }
	~CResult_NetworkGraphDecodeErrorZ() { CResult_NetworkGraphDecodeErrorZ_free(self); }
	CResult_NetworkGraphDecodeErrorZ& operator=(CResult_NetworkGraphDecodeErrorZ&& o) { CResult_NetworkGraphDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NetworkGraphDecodeErrorZ)); return *this; }
	LDKCResult_NetworkGraphDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NetworkGraphDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NetworkGraphDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NetworkGraphDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_MonitorEventZ {
private:
	LDKCVec_MonitorEventZ self;
public:
	CVec_MonitorEventZ(const CVec_MonitorEventZ&) = delete;
	CVec_MonitorEventZ(CVec_MonitorEventZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_MonitorEventZ)); }
	CVec_MonitorEventZ(LDKCVec_MonitorEventZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_MonitorEventZ)); }
	operator LDKCVec_MonitorEventZ() && { LDKCVec_MonitorEventZ res = self; memset(&self, 0, sizeof(LDKCVec_MonitorEventZ)); return res; }
	~CVec_MonitorEventZ() { CVec_MonitorEventZ_free(self); }
	CVec_MonitorEventZ& operator=(CVec_MonitorEventZ&& o) { CVec_MonitorEventZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_MonitorEventZ)); return *this; }
	LDKCVec_MonitorEventZ* operator &() { return &self; }
	LDKCVec_MonitorEventZ* operator ->() { return &self; }
	const LDKCVec_MonitorEventZ* operator &() const { return &self; }
	const LDKCVec_MonitorEventZ* operator ->() const { return &self; }
};
class CResult_ChanKeySignerDecodeErrorZ {
private:
	LDKCResult_ChanKeySignerDecodeErrorZ self;
public:
	CResult_ChanKeySignerDecodeErrorZ(const CResult_ChanKeySignerDecodeErrorZ&) = delete;
	CResult_ChanKeySignerDecodeErrorZ(CResult_ChanKeySignerDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ChanKeySignerDecodeErrorZ)); }
	CResult_ChanKeySignerDecodeErrorZ(LDKCResult_ChanKeySignerDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ChanKeySignerDecodeErrorZ)); }
	operator LDKCResult_ChanKeySignerDecodeErrorZ() && { LDKCResult_ChanKeySignerDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ChanKeySignerDecodeErrorZ)); return res; }
	~CResult_ChanKeySignerDecodeErrorZ() { CResult_ChanKeySignerDecodeErrorZ_free(self); }
	CResult_ChanKeySignerDecodeErrorZ& operator=(CResult_ChanKeySignerDecodeErrorZ&& o) { CResult_ChanKeySignerDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ChanKeySignerDecodeErrorZ)); return *this; }
	LDKCResult_ChanKeySignerDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ChanKeySignerDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ChanKeySignerDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ChanKeySignerDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_RouteHopZ {
private:
	LDKCVec_RouteHopZ self;
public:
	CVec_RouteHopZ(const CVec_RouteHopZ&) = delete;
	CVec_RouteHopZ(CVec_RouteHopZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_RouteHopZ)); }
	CVec_RouteHopZ(LDKCVec_RouteHopZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_RouteHopZ)); }
	operator LDKCVec_RouteHopZ() && { LDKCVec_RouteHopZ res = self; memset(&self, 0, sizeof(LDKCVec_RouteHopZ)); return res; }
	~CVec_RouteHopZ() { CVec_RouteHopZ_free(self); }
	CVec_RouteHopZ& operator=(CVec_RouteHopZ&& o) { CVec_RouteHopZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_RouteHopZ)); return *this; }
	LDKCVec_RouteHopZ* operator &() { return &self; }
	LDKCVec_RouteHopZ* operator ->() { return &self; }
	const LDKCVec_RouteHopZ* operator &() const { return &self; }
	const LDKCVec_RouteHopZ* operator ->() const { return &self; }
};
class CResult_NoneChannelMonitorUpdateErrZ {
private:
	LDKCResult_NoneChannelMonitorUpdateErrZ self;
public:
	CResult_NoneChannelMonitorUpdateErrZ(const CResult_NoneChannelMonitorUpdateErrZ&) = delete;
	CResult_NoneChannelMonitorUpdateErrZ(CResult_NoneChannelMonitorUpdateErrZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneChannelMonitorUpdateErrZ)); }
	CResult_NoneChannelMonitorUpdateErrZ(LDKCResult_NoneChannelMonitorUpdateErrZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneChannelMonitorUpdateErrZ)); }
	operator LDKCResult_NoneChannelMonitorUpdateErrZ() && { LDKCResult_NoneChannelMonitorUpdateErrZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneChannelMonitorUpdateErrZ)); return res; }
	~CResult_NoneChannelMonitorUpdateErrZ() { CResult_NoneChannelMonitorUpdateErrZ_free(self); }
	CResult_NoneChannelMonitorUpdateErrZ& operator=(CResult_NoneChannelMonitorUpdateErrZ&& o) { CResult_NoneChannelMonitorUpdateErrZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneChannelMonitorUpdateErrZ)); return *this; }
	LDKCResult_NoneChannelMonitorUpdateErrZ* operator &() { return &self; }
	LDKCResult_NoneChannelMonitorUpdateErrZ* operator ->() { return &self; }
	const LDKCResult_NoneChannelMonitorUpdateErrZ* operator &() const { return &self; }
	const LDKCResult_NoneChannelMonitorUpdateErrZ* operator ->() const { return &self; }
};
class CResult_NonePaymentSendFailureZ {
private:
	LDKCResult_NonePaymentSendFailureZ self;
public:
	CResult_NonePaymentSendFailureZ(const CResult_NonePaymentSendFailureZ&) = delete;
	CResult_NonePaymentSendFailureZ(CResult_NonePaymentSendFailureZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NonePaymentSendFailureZ)); }
	CResult_NonePaymentSendFailureZ(LDKCResult_NonePaymentSendFailureZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NonePaymentSendFailureZ)); }
	operator LDKCResult_NonePaymentSendFailureZ() && { LDKCResult_NonePaymentSendFailureZ res = self; memset(&self, 0, sizeof(LDKCResult_NonePaymentSendFailureZ)); return res; }
	~CResult_NonePaymentSendFailureZ() { CResult_NonePaymentSendFailureZ_free(self); }
	CResult_NonePaymentSendFailureZ& operator=(CResult_NonePaymentSendFailureZ&& o) { CResult_NonePaymentSendFailureZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NonePaymentSendFailureZ)); return *this; }
	LDKCResult_NonePaymentSendFailureZ* operator &() { return &self; }
	LDKCResult_NonePaymentSendFailureZ* operator ->() { return &self; }
	const LDKCResult_NonePaymentSendFailureZ* operator &() const { return &self; }
	const LDKCResult_NonePaymentSendFailureZ* operator ->() const { return &self; }
};
class CResult_NodeInfoDecodeErrorZ {
private:
	LDKCResult_NodeInfoDecodeErrorZ self;
public:
	CResult_NodeInfoDecodeErrorZ(const CResult_NodeInfoDecodeErrorZ&) = delete;
	CResult_NodeInfoDecodeErrorZ(CResult_NodeInfoDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NodeInfoDecodeErrorZ)); }
	CResult_NodeInfoDecodeErrorZ(LDKCResult_NodeInfoDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NodeInfoDecodeErrorZ)); }
	operator LDKCResult_NodeInfoDecodeErrorZ() && { LDKCResult_NodeInfoDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NodeInfoDecodeErrorZ)); return res; }
	~CResult_NodeInfoDecodeErrorZ() { CResult_NodeInfoDecodeErrorZ_free(self); }
	CResult_NodeInfoDecodeErrorZ& operator=(CResult_NodeInfoDecodeErrorZ&& o) { CResult_NodeInfoDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NodeInfoDecodeErrorZ)); return *this; }
	LDKCResult_NodeInfoDecodeErrorZ* operator &() { return &self; }
	LDKCResult_NodeInfoDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_NodeInfoDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_NodeInfoDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_u8Z {
private:
	LDKCVec_u8Z self;
public:
	CVec_u8Z(const CVec_u8Z&) = delete;
	CVec_u8Z(CVec_u8Z&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_u8Z)); }
	CVec_u8Z(LDKCVec_u8Z&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_u8Z)); }
	operator LDKCVec_u8Z() && { LDKCVec_u8Z res = self; memset(&self, 0, sizeof(LDKCVec_u8Z)); return res; }
	~CVec_u8Z() { CVec_u8Z_free(self); }
	CVec_u8Z& operator=(CVec_u8Z&& o) { CVec_u8Z_free(self); self = o.self; memset(&o, 0, sizeof(CVec_u8Z)); return *this; }
	LDKCVec_u8Z* operator &() { return &self; }
	LDKCVec_u8Z* operator ->() { return &self; }
	const LDKCVec_u8Z* operator &() const { return &self; }
	const LDKCVec_u8Z* operator ->() const { return &self; }
};
class CResult_PublicKeySecpErrorZ {
private:
	LDKCResult_PublicKeySecpErrorZ self;
public:
	CResult_PublicKeySecpErrorZ(const CResult_PublicKeySecpErrorZ&) = delete;
	CResult_PublicKeySecpErrorZ(CResult_PublicKeySecpErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PublicKeySecpErrorZ)); }
	CResult_PublicKeySecpErrorZ(LDKCResult_PublicKeySecpErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PublicKeySecpErrorZ)); }
	operator LDKCResult_PublicKeySecpErrorZ() && { LDKCResult_PublicKeySecpErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PublicKeySecpErrorZ)); return res; }
	~CResult_PublicKeySecpErrorZ() { CResult_PublicKeySecpErrorZ_free(self); }
	CResult_PublicKeySecpErrorZ& operator=(CResult_PublicKeySecpErrorZ&& o) { CResult_PublicKeySecpErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PublicKeySecpErrorZ)); return *this; }
	LDKCResult_PublicKeySecpErrorZ* operator &() { return &self; }
	LDKCResult_PublicKeySecpErrorZ* operator ->() { return &self; }
	const LDKCResult_PublicKeySecpErrorZ* operator &() const { return &self; }
	const LDKCResult_PublicKeySecpErrorZ* operator ->() const { return &self; }
};
class CResult_RouteLightningErrorZ {
private:
	LDKCResult_RouteLightningErrorZ self;
public:
	CResult_RouteLightningErrorZ(const CResult_RouteLightningErrorZ&) = delete;
	CResult_RouteLightningErrorZ(CResult_RouteLightningErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RouteLightningErrorZ)); }
	CResult_RouteLightningErrorZ(LDKCResult_RouteLightningErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RouteLightningErrorZ)); }
	operator LDKCResult_RouteLightningErrorZ() && { LDKCResult_RouteLightningErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RouteLightningErrorZ)); return res; }
	~CResult_RouteLightningErrorZ() { CResult_RouteLightningErrorZ_free(self); }
	CResult_RouteLightningErrorZ& operator=(CResult_RouteLightningErrorZ&& o) { CResult_RouteLightningErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RouteLightningErrorZ)); return *this; }
	LDKCResult_RouteLightningErrorZ* operator &() { return &self; }
	LDKCResult_RouteLightningErrorZ* operator ->() { return &self; }
	const LDKCResult_RouteLightningErrorZ* operator &() const { return &self; }
	const LDKCResult_RouteLightningErrorZ* operator ->() const { return &self; }
};
class C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
private:
	LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ self;
public:
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ(const C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ&) = delete;
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ(C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ&& o) : self(o.self) { memset(&o, 0, sizeof(C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ)); }
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ(LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ)); }
	operator LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ() && { LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ res = self; memset(&self, 0, sizeof(LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ)); return res; }
	~C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ() { C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_free(self); }
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ& operator=(C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ&& o) { C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_free(self); self = o.self; memset(&o, 0, sizeof(C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ)); return *this; }
	LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ* operator &() { return &self; }
	LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ* operator ->() { return &self; }
	const LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ* operator &() const { return &self; }
	const LDKC3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ* operator ->() const { return &self; }
};
class CResult_boolPeerHandleErrorZ {
private:
	LDKCResult_boolPeerHandleErrorZ self;
public:
	CResult_boolPeerHandleErrorZ(const CResult_boolPeerHandleErrorZ&) = delete;
	CResult_boolPeerHandleErrorZ(CResult_boolPeerHandleErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_boolPeerHandleErrorZ)); }
	CResult_boolPeerHandleErrorZ(LDKCResult_boolPeerHandleErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_boolPeerHandleErrorZ)); }
	operator LDKCResult_boolPeerHandleErrorZ() && { LDKCResult_boolPeerHandleErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_boolPeerHandleErrorZ)); return res; }
	~CResult_boolPeerHandleErrorZ() { CResult_boolPeerHandleErrorZ_free(self); }
	CResult_boolPeerHandleErrorZ& operator=(CResult_boolPeerHandleErrorZ&& o) { CResult_boolPeerHandleErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_boolPeerHandleErrorZ)); return *this; }
	LDKCResult_boolPeerHandleErrorZ* operator &() { return &self; }
	LDKCResult_boolPeerHandleErrorZ* operator ->() { return &self; }
	const LDKCResult_boolPeerHandleErrorZ* operator &() const { return &self; }
	const LDKCResult_boolPeerHandleErrorZ* operator ->() const { return &self; }
};
class CVec_UpdateFulfillHTLCZ {
private:
	LDKCVec_UpdateFulfillHTLCZ self;
public:
	CVec_UpdateFulfillHTLCZ(const CVec_UpdateFulfillHTLCZ&) = delete;
	CVec_UpdateFulfillHTLCZ(CVec_UpdateFulfillHTLCZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_UpdateFulfillHTLCZ)); }
	CVec_UpdateFulfillHTLCZ(LDKCVec_UpdateFulfillHTLCZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_UpdateFulfillHTLCZ)); }
	operator LDKCVec_UpdateFulfillHTLCZ() && { LDKCVec_UpdateFulfillHTLCZ res = self; memset(&self, 0, sizeof(LDKCVec_UpdateFulfillHTLCZ)); return res; }
	~CVec_UpdateFulfillHTLCZ() { CVec_UpdateFulfillHTLCZ_free(self); }
	CVec_UpdateFulfillHTLCZ& operator=(CVec_UpdateFulfillHTLCZ&& o) { CVec_UpdateFulfillHTLCZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_UpdateFulfillHTLCZ)); return *this; }
	LDKCVec_UpdateFulfillHTLCZ* operator &() { return &self; }
	LDKCVec_UpdateFulfillHTLCZ* operator ->() { return &self; }
	const LDKCVec_UpdateFulfillHTLCZ* operator &() const { return &self; }
	const LDKCVec_UpdateFulfillHTLCZ* operator ->() const { return &self; }
};
class CResult_SignatureNoneZ {
private:
	LDKCResult_SignatureNoneZ self;
public:
	CResult_SignatureNoneZ(const CResult_SignatureNoneZ&) = delete;
	CResult_SignatureNoneZ(CResult_SignatureNoneZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_SignatureNoneZ)); }
	CResult_SignatureNoneZ(LDKCResult_SignatureNoneZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_SignatureNoneZ)); }
	operator LDKCResult_SignatureNoneZ() && { LDKCResult_SignatureNoneZ res = self; memset(&self, 0, sizeof(LDKCResult_SignatureNoneZ)); return res; }
	~CResult_SignatureNoneZ() { CResult_SignatureNoneZ_free(self); }
	CResult_SignatureNoneZ& operator=(CResult_SignatureNoneZ&& o) { CResult_SignatureNoneZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_SignatureNoneZ)); return *this; }
	LDKCResult_SignatureNoneZ* operator &() { return &self; }
	LDKCResult_SignatureNoneZ* operator ->() { return &self; }
	const LDKCResult_SignatureNoneZ* operator &() const { return &self; }
	const LDKCResult_SignatureNoneZ* operator ->() const { return &self; }
};
class C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
private:
	LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ self;
public:
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ(const C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ&) = delete;
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ(C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ)); }
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ(LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ)); }
	operator LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ() && { LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ)); return res; }
	~C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ() { C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_free(self); }
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ& operator=(C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ&& o) { C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ)); return *this; }
	LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ* operator &() { return &self; }
	LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ* operator ->() { return &self; }
	const LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ* operator &() const { return &self; }
	const LDKC2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ* operator ->() const { return &self; }
};
class CResult_InitDecodeErrorZ {
private:
	LDKCResult_InitDecodeErrorZ self;
public:
	CResult_InitDecodeErrorZ(const CResult_InitDecodeErrorZ&) = delete;
	CResult_InitDecodeErrorZ(CResult_InitDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InitDecodeErrorZ)); }
	CResult_InitDecodeErrorZ(LDKCResult_InitDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InitDecodeErrorZ)); }
	operator LDKCResult_InitDecodeErrorZ() && { LDKCResult_InitDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InitDecodeErrorZ)); return res; }
	~CResult_InitDecodeErrorZ() { CResult_InitDecodeErrorZ_free(self); }
	CResult_InitDecodeErrorZ& operator=(CResult_InitDecodeErrorZ&& o) { CResult_InitDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InitDecodeErrorZ)); return *this; }
	LDKCResult_InitDecodeErrorZ* operator &() { return &self; }
	LDKCResult_InitDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_InitDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_InitDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_ReplyShortChannelIdsEndDecodeErrorZ {
private:
	LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ self;
public:
	CResult_ReplyShortChannelIdsEndDecodeErrorZ(const CResult_ReplyShortChannelIdsEndDecodeErrorZ&) = delete;
	CResult_ReplyShortChannelIdsEndDecodeErrorZ(CResult_ReplyShortChannelIdsEndDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_ReplyShortChannelIdsEndDecodeErrorZ)); }
	CResult_ReplyShortChannelIdsEndDecodeErrorZ(LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ)); }
	operator LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ() && { LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ)); return res; }
	~CResult_ReplyShortChannelIdsEndDecodeErrorZ() { CResult_ReplyShortChannelIdsEndDecodeErrorZ_free(self); }
	CResult_ReplyShortChannelIdsEndDecodeErrorZ& operator=(CResult_ReplyShortChannelIdsEndDecodeErrorZ&& o) { CResult_ReplyShortChannelIdsEndDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_ReplyShortChannelIdsEndDecodeErrorZ)); return *this; }
	LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ* operator &() { return &self; }
	LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_ReplyShortChannelIdsEndDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_CResult_NetAddressu8ZDecodeErrorZ {
private:
	LDKCResult_CResult_NetAddressu8ZDecodeErrorZ self;
public:
	CResult_CResult_NetAddressu8ZDecodeErrorZ(const CResult_CResult_NetAddressu8ZDecodeErrorZ&) = delete;
	CResult_CResult_NetAddressu8ZDecodeErrorZ(CResult_CResult_NetAddressu8ZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_CResult_NetAddressu8ZDecodeErrorZ)); }
	CResult_CResult_NetAddressu8ZDecodeErrorZ(LDKCResult_CResult_NetAddressu8ZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_CResult_NetAddressu8ZDecodeErrorZ)); }
	operator LDKCResult_CResult_NetAddressu8ZDecodeErrorZ() && { LDKCResult_CResult_NetAddressu8ZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_CResult_NetAddressu8ZDecodeErrorZ)); return res; }
	~CResult_CResult_NetAddressu8ZDecodeErrorZ() { CResult_CResult_NetAddressu8ZDecodeErrorZ_free(self); }
	CResult_CResult_NetAddressu8ZDecodeErrorZ& operator=(CResult_CResult_NetAddressu8ZDecodeErrorZ&& o) { CResult_CResult_NetAddressu8ZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_CResult_NetAddressu8ZDecodeErrorZ)); return *this; }
	LDKCResult_CResult_NetAddressu8ZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_CResult_NetAddressu8ZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_CResult_NetAddressu8ZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_CResult_NetAddressu8ZDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_ChannelDetailsZ {
private:
	LDKCVec_ChannelDetailsZ self;
public:
	CVec_ChannelDetailsZ(const CVec_ChannelDetailsZ&) = delete;
	CVec_ChannelDetailsZ(CVec_ChannelDetailsZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_ChannelDetailsZ)); }
	CVec_ChannelDetailsZ(LDKCVec_ChannelDetailsZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_ChannelDetailsZ)); }
	operator LDKCVec_ChannelDetailsZ() && { LDKCVec_ChannelDetailsZ res = self; memset(&self, 0, sizeof(LDKCVec_ChannelDetailsZ)); return res; }
	~CVec_ChannelDetailsZ() { CVec_ChannelDetailsZ_free(self); }
	CVec_ChannelDetailsZ& operator=(CVec_ChannelDetailsZ&& o) { CVec_ChannelDetailsZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_ChannelDetailsZ)); return *this; }
	LDKCVec_ChannelDetailsZ* operator &() { return &self; }
	LDKCVec_ChannelDetailsZ* operator ->() { return &self; }
	const LDKCVec_ChannelDetailsZ* operator &() const { return &self; }
	const LDKCVec_ChannelDetailsZ* operator ->() const { return &self; }
};
class CVec_MessageSendEventZ {
private:
	LDKCVec_MessageSendEventZ self;
public:
	CVec_MessageSendEventZ(const CVec_MessageSendEventZ&) = delete;
	CVec_MessageSendEventZ(CVec_MessageSendEventZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_MessageSendEventZ)); }
	CVec_MessageSendEventZ(LDKCVec_MessageSendEventZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_MessageSendEventZ)); }
	operator LDKCVec_MessageSendEventZ() && { LDKCVec_MessageSendEventZ res = self; memset(&self, 0, sizeof(LDKCVec_MessageSendEventZ)); return res; }
	~CVec_MessageSendEventZ() { CVec_MessageSendEventZ_free(self); }
	CVec_MessageSendEventZ& operator=(CVec_MessageSendEventZ&& o) { CVec_MessageSendEventZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_MessageSendEventZ)); return *this; }
	LDKCVec_MessageSendEventZ* operator &() { return &self; }
	LDKCVec_MessageSendEventZ* operator ->() { return &self; }
	const LDKCVec_MessageSendEventZ* operator &() const { return &self; }
	const LDKCVec_MessageSendEventZ* operator ->() const { return &self; }
};
class CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ {
private:
	LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ self;
public:
	CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ(const CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ&) = delete;
	CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ(CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ)); }
	CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ(LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ)); }
	operator LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ() && { LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ res = self; memset(&self, 0, sizeof(LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ)); return res; }
	~CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ() { CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ_free(self); }
	CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ& operator=(CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ&& o) { CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ)); return *this; }
	LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ* operator &() { return &self; }
	LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ* operator ->() { return &self; }
	const LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ* operator &() const { return &self; }
	const LDKCVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ* operator ->() const { return &self; }
};
class CVec_UpdateFailHTLCZ {
private:
	LDKCVec_UpdateFailHTLCZ self;
public:
	CVec_UpdateFailHTLCZ(const CVec_UpdateFailHTLCZ&) = delete;
	CVec_UpdateFailHTLCZ(CVec_UpdateFailHTLCZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_UpdateFailHTLCZ)); }
	CVec_UpdateFailHTLCZ(LDKCVec_UpdateFailHTLCZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_UpdateFailHTLCZ)); }
	operator LDKCVec_UpdateFailHTLCZ() && { LDKCVec_UpdateFailHTLCZ res = self; memset(&self, 0, sizeof(LDKCVec_UpdateFailHTLCZ)); return res; }
	~CVec_UpdateFailHTLCZ() { CVec_UpdateFailHTLCZ_free(self); }
	CVec_UpdateFailHTLCZ& operator=(CVec_UpdateFailHTLCZ&& o) { CVec_UpdateFailHTLCZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_UpdateFailHTLCZ)); return *this; }
	LDKCVec_UpdateFailHTLCZ* operator &() { return &self; }
	LDKCVec_UpdateFailHTLCZ* operator ->() { return &self; }
	const LDKCVec_UpdateFailHTLCZ* operator &() const { return &self; }
	const LDKCVec_UpdateFailHTLCZ* operator ->() const { return &self; }
};
class C2Tuple_OutPointScriptZ {
private:
	LDKC2Tuple_OutPointScriptZ self;
public:
	C2Tuple_OutPointScriptZ(const C2Tuple_OutPointScriptZ&) = delete;
	C2Tuple_OutPointScriptZ(C2Tuple_OutPointScriptZ&& o) : self(o.self) { memset(&o, 0, sizeof(C2Tuple_OutPointScriptZ)); }
	C2Tuple_OutPointScriptZ(LDKC2Tuple_OutPointScriptZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKC2Tuple_OutPointScriptZ)); }
	operator LDKC2Tuple_OutPointScriptZ() && { LDKC2Tuple_OutPointScriptZ res = self; memset(&self, 0, sizeof(LDKC2Tuple_OutPointScriptZ)); return res; }
	~C2Tuple_OutPointScriptZ() { C2Tuple_OutPointScriptZ_free(self); }
	C2Tuple_OutPointScriptZ& operator=(C2Tuple_OutPointScriptZ&& o) { C2Tuple_OutPointScriptZ_free(self); self = o.self; memset(&o, 0, sizeof(C2Tuple_OutPointScriptZ)); return *this; }
	LDKC2Tuple_OutPointScriptZ* operator &() { return &self; }
	LDKC2Tuple_OutPointScriptZ* operator ->() { return &self; }
	const LDKC2Tuple_OutPointScriptZ* operator &() const { return &self; }
	const LDKC2Tuple_OutPointScriptZ* operator ->() const { return &self; }
};
class CResult_InMemoryChannelKeysDecodeErrorZ {
private:
	LDKCResult_InMemoryChannelKeysDecodeErrorZ self;
public:
	CResult_InMemoryChannelKeysDecodeErrorZ(const CResult_InMemoryChannelKeysDecodeErrorZ&) = delete;
	CResult_InMemoryChannelKeysDecodeErrorZ(CResult_InMemoryChannelKeysDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_InMemoryChannelKeysDecodeErrorZ)); }
	CResult_InMemoryChannelKeysDecodeErrorZ(LDKCResult_InMemoryChannelKeysDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_InMemoryChannelKeysDecodeErrorZ)); }
	operator LDKCResult_InMemoryChannelKeysDecodeErrorZ() && { LDKCResult_InMemoryChannelKeysDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_InMemoryChannelKeysDecodeErrorZ)); return res; }
	~CResult_InMemoryChannelKeysDecodeErrorZ() { CResult_InMemoryChannelKeysDecodeErrorZ_free(self); }
	CResult_InMemoryChannelKeysDecodeErrorZ& operator=(CResult_InMemoryChannelKeysDecodeErrorZ&& o) { CResult_InMemoryChannelKeysDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_InMemoryChannelKeysDecodeErrorZ)); return *this; }
	LDKCResult_InMemoryChannelKeysDecodeErrorZ* operator &() { return &self; }
	LDKCResult_InMemoryChannelKeysDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_InMemoryChannelKeysDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_InMemoryChannelKeysDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
private:
	LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ self;
public:
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ(const CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ&) = delete;
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ(CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ)); }
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ(LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ)); }
	operator LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ() && { LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ)); return res; }
	~CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ() { CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_free(self); }
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ& operator=(CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ&& o) { CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ)); return *this; }
	LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ* operator &() { return &self; }
	LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_RouteDecodeErrorZ {
private:
	LDKCResult_RouteDecodeErrorZ self;
public:
	CResult_RouteDecodeErrorZ(const CResult_RouteDecodeErrorZ&) = delete;
	CResult_RouteDecodeErrorZ(CResult_RouteDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_RouteDecodeErrorZ)); }
	CResult_RouteDecodeErrorZ(LDKCResult_RouteDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_RouteDecodeErrorZ)); }
	operator LDKCResult_RouteDecodeErrorZ() && { LDKCResult_RouteDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_RouteDecodeErrorZ)); return res; }
	~CResult_RouteDecodeErrorZ() { CResult_RouteDecodeErrorZ_free(self); }
	CResult_RouteDecodeErrorZ& operator=(CResult_RouteDecodeErrorZ&& o) { CResult_RouteDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_RouteDecodeErrorZ)); return *this; }
	LDKCResult_RouteDecodeErrorZ* operator &() { return &self; }
	LDKCResult_RouteDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_RouteDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_RouteDecodeErrorZ* operator ->() const { return &self; }
};
class CVec_NodeAnnouncementZ {
private:
	LDKCVec_NodeAnnouncementZ self;
public:
	CVec_NodeAnnouncementZ(const CVec_NodeAnnouncementZ&) = delete;
	CVec_NodeAnnouncementZ(CVec_NodeAnnouncementZ&& o) : self(o.self) { memset(&o, 0, sizeof(CVec_NodeAnnouncementZ)); }
	CVec_NodeAnnouncementZ(LDKCVec_NodeAnnouncementZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCVec_NodeAnnouncementZ)); }
	operator LDKCVec_NodeAnnouncementZ() && { LDKCVec_NodeAnnouncementZ res = self; memset(&self, 0, sizeof(LDKCVec_NodeAnnouncementZ)); return res; }
	~CVec_NodeAnnouncementZ() { CVec_NodeAnnouncementZ_free(self); }
	CVec_NodeAnnouncementZ& operator=(CVec_NodeAnnouncementZ&& o) { CVec_NodeAnnouncementZ_free(self); self = o.self; memset(&o, 0, sizeof(CVec_NodeAnnouncementZ)); return *this; }
	LDKCVec_NodeAnnouncementZ* operator &() { return &self; }
	LDKCVec_NodeAnnouncementZ* operator ->() { return &self; }
	const LDKCVec_NodeAnnouncementZ* operator &() const { return &self; }
	const LDKCVec_NodeAnnouncementZ* operator ->() const { return &self; }
};
class CResult_UnsignedChannelAnnouncementDecodeErrorZ {
private:
	LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ self;
public:
	CResult_UnsignedChannelAnnouncementDecodeErrorZ(const CResult_UnsignedChannelAnnouncementDecodeErrorZ&) = delete;
	CResult_UnsignedChannelAnnouncementDecodeErrorZ(CResult_UnsignedChannelAnnouncementDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_UnsignedChannelAnnouncementDecodeErrorZ)); }
	CResult_UnsignedChannelAnnouncementDecodeErrorZ(LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ)); }
	operator LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ() && { LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ)); return res; }
	~CResult_UnsignedChannelAnnouncementDecodeErrorZ() { CResult_UnsignedChannelAnnouncementDecodeErrorZ_free(self); }
	CResult_UnsignedChannelAnnouncementDecodeErrorZ& operator=(CResult_UnsignedChannelAnnouncementDecodeErrorZ&& o) { CResult_UnsignedChannelAnnouncementDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_UnsignedChannelAnnouncementDecodeErrorZ)); return *this; }
	LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ* operator &() { return &self; }
	LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_UnsignedChannelAnnouncementDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_PongDecodeErrorZ {
private:
	LDKCResult_PongDecodeErrorZ self;
public:
	CResult_PongDecodeErrorZ(const CResult_PongDecodeErrorZ&) = delete;
	CResult_PongDecodeErrorZ(CResult_PongDecodeErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_PongDecodeErrorZ)); }
	CResult_PongDecodeErrorZ(LDKCResult_PongDecodeErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_PongDecodeErrorZ)); }
	operator LDKCResult_PongDecodeErrorZ() && { LDKCResult_PongDecodeErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_PongDecodeErrorZ)); return res; }
	~CResult_PongDecodeErrorZ() { CResult_PongDecodeErrorZ_free(self); }
	CResult_PongDecodeErrorZ& operator=(CResult_PongDecodeErrorZ&& o) { CResult_PongDecodeErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_PongDecodeErrorZ)); return *this; }
	LDKCResult_PongDecodeErrorZ* operator &() { return &self; }
	LDKCResult_PongDecodeErrorZ* operator ->() { return &self; }
	const LDKCResult_PongDecodeErrorZ* operator &() const { return &self; }
	const LDKCResult_PongDecodeErrorZ* operator ->() const { return &self; }
};
class CResult_NoneMonitorUpdateErrorZ {
private:
	LDKCResult_NoneMonitorUpdateErrorZ self;
public:
	CResult_NoneMonitorUpdateErrorZ(const CResult_NoneMonitorUpdateErrorZ&) = delete;
	CResult_NoneMonitorUpdateErrorZ(CResult_NoneMonitorUpdateErrorZ&& o) : self(o.self) { memset(&o, 0, sizeof(CResult_NoneMonitorUpdateErrorZ)); }
	CResult_NoneMonitorUpdateErrorZ(LDKCResult_NoneMonitorUpdateErrorZ&& m_self) : self(m_self) { memset(&m_self, 0, sizeof(LDKCResult_NoneMonitorUpdateErrorZ)); }
	operator LDKCResult_NoneMonitorUpdateErrorZ() && { LDKCResult_NoneMonitorUpdateErrorZ res = self; memset(&self, 0, sizeof(LDKCResult_NoneMonitorUpdateErrorZ)); return res; }
	~CResult_NoneMonitorUpdateErrorZ() { CResult_NoneMonitorUpdateErrorZ_free(self); }
	CResult_NoneMonitorUpdateErrorZ& operator=(CResult_NoneMonitorUpdateErrorZ&& o) { CResult_NoneMonitorUpdateErrorZ_free(self); self = o.self; memset(&o, 0, sizeof(CResult_NoneMonitorUpdateErrorZ)); return *this; }
	LDKCResult_NoneMonitorUpdateErrorZ* operator &() { return &self; }
	LDKCResult_NoneMonitorUpdateErrorZ* operator ->() { return &self; }
	const LDKCResult_NoneMonitorUpdateErrorZ* operator &() const { return &self; }
	const LDKCResult_NoneMonitorUpdateErrorZ* operator ->() const { return &self; }
};
}
