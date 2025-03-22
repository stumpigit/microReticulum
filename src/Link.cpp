#include "Link.h"

#include "Reticulum.h"
#include "Transport.h"
#include "Packet.h"
#include "Utilities/OS.h"
#include "Log.h"

using namespace RNS;
using namespace RNS::Type::Link;

uint8_t Link::resource_strategies = Type::Link::ACCEPT_NONE | Type::Link::ACCEPT_APP | Type::Link::ACCEPT_ALL;

Link::Link(const Destination& destination /*= {Type::NONE}*/, Callbacks::established established_callback /*= nullptr*/, Callbacks::closed closed_callback /*= nullptr*/, const Destination& owner /*= {Type::NONE}*/, const Bytes& peer_pub_bytes /*= {Bytes::NONE}*/, const Bytes& peer_sig_pub_bytes /*= {Bytes::NONE}*/) : _object(new Object(destination)) {
	assert(_object);

	MEM("Link object created");
	_object->_owner = owner;

	if (destination && destination.type() != Type::Destination::SINGLE) {
		throw std::logic_error("Links can only be established to the \"single\" destination type");
	}

	if (!destination) {
		_object->_initiator = false;
		_object->_prv     = Cryptography::X25519PrivateKey::generate();
		// CBA BUG: not checking for owner
		if (_object->_owner) {
			_object->_sig_prv = _object->_owner.identity().sig_prv();
		}
	}
	else {
		_object->_initiator = true;
		_object->_expected_hops = Transport::hops_to(_object->_destination.hash());
		
		int base_timeout = Transport::first_hop_timeout(_object->_destination.hash());
		_object->establishment_timeout = base_timeout + ESTABLISHMENT_TIMEOUT_PER_HOP * _max(1, RNS::Transport::hops_to(_object->_destination.hash()));
		_object->_prv     = Cryptography::X25519PrivateKey::generate();
		_object->_sig_prv = Cryptography::Ed25519PrivateKey::generate();
	}

	// CS TODO
	//_object->_fernet  = None

	_object->_pub = _object->_prv->public_key();
	_object->_pub_bytes = _object->_pub->public_bytes();

	_object->_sig_pub = _object->_sig_prv->public_key();
	_object->_sig_pub_bytes = _object->_sig_pub->public_bytes();

	if (!peer_pub_bytes.empty())
		_object->_peer_pub = nullptr;
		//_object->_peer_pub_bytes = None
	else
		// CS TODO
		// _object->_load_peer(peer_pub_bytes, peer_sig_pub_bytes)

	if (established_callback != nullptr)
		// CS TODO
		// _object->_set_link_established_callback(established_callback);

	if (closed_callback != nullptr)
		// CS TODO
		// _object->_set_link_closed_callback(closed_callback);

	if (_object->_initiator) {
		_object->_request_data = _object->_pub_bytes+_object->_sig_pub_bytes;
		_object->_packet = RNS::Packet(destination, _object->_request_data, Type::Packet::LINKREQUEST);
		_object->_packet.pack();
		_object->_establishment_cost += _object->_packet.raw().size();
		set_link_id(_object->_packet);
		RNS::Transport::register_link(*this);

		_object->_request_time = RNS::Utilities::OS::ltime();
		
		//CS TODO
		//_object->_start_watchdog();
		_object->_packet.send();
		had_outbound();
		DEBUG("Link request "+_object->_link_id.toHex()+" sent to "+_object->_destination.toString());
		DEBUG("Establishment timeout is {RNS.prettytime(_object->_establishment_timeout)} for link request "+_object->_link_id.toHex());
	}

	MEM("Link object created");

}


/*p TODO
Link::validate_request(owner, data, packet) {
	if len(data) == (Link.ECPUBSIZE):
		try:
			link = Link(owner = owner, peer_pub_bytes=data[:Link.ECPUBSIZE//2], peer_sig_pub_bytes=data[Link.ECPUBSIZE//2:Link.ECPUBSIZE])
			link.set_link_id(packet)
			link.destination = packet.destination
			link.establishment_timeout = Link.ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, packet.hops) + Link.KEEPALIVE
			link.establishment_cost += len(packet.raw)
			RNS.log("Validating link request "+RNS.prettyhexrep(link.link_id), RNS.LOG_VERBOSE)
			RNS.log(f"Establishment timeout is {RNS.prettytime(link.establishment_timeout)} for incoming link request "+RNS.prettyhexrep(link.link_id), RNS.LOG_EXTREME)
			link.handshake()
			link.attached_interface = packet.receiving_interface
			link.prove()
			link.request_time = time.time()
			RNS.Transport.register_link(link)
			link.last_inbound = time.time()
			link.start_watchdog()
			
			RNS.log("Incoming link request "+str(link)+" accepted", RNS.LOG_DEBUG)
			return link

		except Exception as e:
			RNS.log("Validating link request failed", RNS.LOG_VERBOSE)
			RNS.log("exc: "+str(e))
			return None

	else:
		RNS.log("Invalid link request payload size, dropping request", RNS.LOG_DEBUG)
		return None
}
*/

void Link::set_link_id(const Packet& packet) {
	assert(_object);
	_object->_link_id = packet.getTruncatedHash();
	_object->_hash = _object->_link_id;
}

void Link::receive(const Packet& packet) {
}

void Link::prove() {
/*p TODO
	signed_data = _object->_link_id+_object->_pub_bytes+_object->_sig_pub_bytes
	signature = _object->_owner.identity.sign(signed_data)

	proof_data = signature+_object->_pub_bytes
	proof = RNS.Packet(self, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF)
	proof.send()
	_object->_establishment_cost += len(proof.raw)
	_object->_had_outbound()
*/
}

void Link::prove_packet(const Packet& packet) {
/*p TODO
	signature = _object->_sign(packet.packet_hash)
	# TODO: Hardcoded as explicit proof for now
	# if RNS.Reticulum.should_use_implicit_proof():
	#   proof_data = signature
	# else:
	#   proof_data = packet.packet_hash + signature
	proof_data = packet.packet_hash + signature

	proof = RNS.Packet(self, proof_data, RNS.Packet.PROOF)
	proof.send()
	_object->_had_outbound()
*/
}

/*p TODO

def load_peer(self, peer_pub_bytes, peer_sig_pub_bytes):
	_object->_peer_pub_bytes = peer_pub_bytes
	_object->_peer_pub = X25519PublicKey.from_public_bytes(_object->_peer_pub_bytes)

	_object->_peer_sig_pub_bytes = peer_sig_pub_bytes
	_object->_peer_sig_pub = Ed25519PublicKey.from_public_bytes(_object->_peer_sig_pub_bytes)

	if not hasattr(_object->_peer_pub, "curve"):
		_object->_peer_pub.curve = Link.CURVE

def set_link_id(self, packet):
	_object->_link_id = packet.getTruncatedHash()
	_object->_hash = _object->_link_id

def handshake(self):
	if _object->_status == Link.PENDING and _object->_prv != None:
		_object->_status = Link.HANDSHAKE
		_object->_shared_key = _object->_prv.exchange(_object->_peer_pub)

		_object->_derived_key = RNS.Cryptography.hkdf(
			length=32,
			derive_from=_object->_shared_key,
			salt=_object->_get_salt(),
			context=_object->_get_context(),
		)
	else:
		RNS.log("Handshake attempt on "+str(self)+" with invalid state "+str(_object->_status), RNS.LOG_ERROR)


def prove(self):
	signed_data = _object->_link_id+_object->_pub_bytes+_object->_sig_pub_bytes
	signature = _object->_owner.identity.sign(signed_data)

	proof_data = signature+_object->_pub_bytes
	proof = RNS.Packet(self, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF)
	proof.send()
	_object->_establishment_cost += len(proof.raw)
	_object->_had_outbound()


def prove_packet(self, packet):
	signature = _object->_sign(packet.packet_hash)
	# TODO: Hardcoded as explicit proof for now
	# if RNS.Reticulum.should_use_implicit_proof():
	#   proof_data = signature
	# else:
	#   proof_data = packet.packet_hash + signature
	proof_data = packet.packet_hash + signature

	proof = RNS.Packet(self, proof_data, RNS.Packet.PROOF)
	proof.send()
	_object->_had_outbound()

def validate_proof(self, packet):
	try:
		if _object->_status == Link.PENDING:
			if _object->_initiator and len(packet.data) == RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2:
				peer_pub_bytes = packet.data[RNS.Identity.SIGLENGTH//8:RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2]
				peer_sig_pub_bytes = _object->_destination.identity.get_public_key()[Link.ECPUBSIZE//2:Link.ECPUBSIZE]
				_object->_load_peer(peer_pub_bytes, peer_sig_pub_bytes)
				_object->_handshake()

				_object->_establishment_cost += len(packet.raw)
				signed_data = _object->_link_id+_object->_peer_pub_bytes+_object->_peer_sig_pub_bytes
				signature = packet.data[:RNS.Identity.SIGLENGTH//8]
				
				if _object->_destination.identity.validate(signature, signed_data):
					if _object->_status != Link.HANDSHAKE:
						raise IOError("Invalid link state for proof validation: "+str(_object->_status))

					_object->_rtt = time.time() - _object->_request_time
					_object->_attached_interface = packet.receiving_interface
					_object->___remote_identity = _object->_destination.identity
					_object->_status = Link.ACTIVE
					_object->_activated_at = time.time()
					_object->_last_proof = _object->_activated_at
					RNS.Transport.activate_link(self)
					RNS.log("Link "+str(self)+" established with "+str(_object->_destination)+", RTT is "+str(round(_object->_rtt, 3))+"s", RNS.LOG_VERBOSE)
					
					if _object->_rtt != None and _object->_establishment_cost != None and _object->_rtt > 0 and _object->_establishment_cost > 0:
						_object->_establishment_rate = _object->_establishment_cost/_object->_rtt

					rtt_data = umsgpack.packb(_object->_rtt)
					rtt_packet = RNS.Packet(self, rtt_data, context=RNS.Packet.LRRTT)
					rtt_packet.send()
					_object->_had_outbound()

					if _object->_callbacks.link_established != None:
						thread = threading.Thread(target=_object->_callbacks.link_established, args=(self,))
						thread.daemon = True
						thread.start()
				else:
					RNS.log("Invalid link proof signature received by "+str(self)+". Ignoring.", RNS.LOG_DEBUG)
	
	except Exception as e:
		_object->_status = Link.CLOSED
		RNS.log("An error ocurred while validating link request proof on "+str(self)+".", RNS.LOG_ERROR)
		RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)


def identify(self, identity):
	"""
	Identifies the initiator of the link to the remote peer. This can only happen
	once the link has been established, and is carried out over the encrypted link.
	The identity is only revealed to the remote peer, and initiator anonymity is
	thus preserved. This method can be used for authentication.

	:param identity: An RNS.Identity instance to identify as.
	"""
	if _object->_initiator and _object->_status == Link.ACTIVE:
		signed_data = _object->_link_id + identity.get_public_key()
		signature = identity.sign(signed_data)
		proof_data = identity.get_public_key() + signature

		proof = RNS.Packet(self, proof_data, RNS.Packet.DATA, context = RNS.Packet.LINKIDENTIFY)
		proof.send()
		_object->_had_outbound()


def request(self, path, data = None, response_callback = None, failed_callback = None, progress_callback = None, timeout = None):
	"""
	Sends a request to the remote peer.

	:param path: The request path.
	:param response_callback: An optional function or method with the signature *response_callback(request_receipt)* to be called when a response is received. See the :ref:`Request Example<example-request>` for more info.
	:param failed_callback: An optional function or method with the signature *failed_callback(request_receipt)* to be called when a request fails. See the :ref:`Request Example<example-request>` for more info.
	:param progress_callback: An optional function or method with the signature *progress_callback(request_receipt)* to be called when progress is made receiving the response. Progress can be accessed as a float between 0.0 and 1.0 by the *request_receipt.progress* property.
	:param timeout: An optional timeout in seconds for the request. If *None* is supplied it will be calculated based on link RTT.
	:returns: A :ref:`RNS.RequestReceipt<api-requestreceipt>` instance if the request was sent, or *False* if it was not.
	"""
	request_path_hash = RNS.Identity.truncated_hash(path.encode("utf-8"))
	unpacked_request  = [time.time(), request_path_hash, data]
	packed_request    = umsgpack.packb(unpacked_request)

	if timeout == None:
		timeout = _object->_rtt * _object->_traffic_timeout_factor + RNS.Resource.RESPONSE_MAX_GRACE_TIME*1.125

	if len(packed_request) <= Link.MDU:
		request_packet   = RNS.Packet(self, packed_request, RNS.Packet.DATA, context = RNS.Packet.REQUEST)
		packet_receipt   = request_packet.send()

		if packet_receipt == False:
			return False
		else:
			packet_receipt.set_timeout(timeout)
			return RequestReceipt(
				self,
				packet_receipt = packet_receipt,
				response_callback = response_callback,
				failed_callback = failed_callback,
				progress_callback = progress_callback,
				timeout = timeout,
				request_size = len(packed_request),
			)
		
	else:
		request_id = RNS.Identity.truncated_hash(packed_request)
		RNS.log("Sending request "+RNS.prettyhexrep(request_id)+" as resource.", RNS.LOG_DEBUG)
		request_resource = RNS.Resource(packed_request, self, request_id = request_id, is_response = False, timeout = timeout)

		return RequestReceipt(
			self,
			resource = request_resource,
			response_callback = response_callback,
			failed_callback = failed_callback,
			progress_callback = progress_callback,
			timeout = timeout,
			request_size = len(packed_request),
		)


def rtt_packet(self, packet):
	try:
		measured_rtt = time.time() - _object->_request_time
		plaintext = _object->_decrypt(packet.data)
		if plaintext != None:
			rtt = umsgpack.unpackb(plaintext)
			_object->_rtt = max(measured_rtt, rtt)
			_object->_status = Link.ACTIVE
			_object->_activated_at = time.time()

			if _object->_rtt != None and _object->_establishment_cost != None and _object->_rtt > 0 and _object->_establishment_cost > 0:
				_object->_establishment_rate = _object->_establishment_cost/_object->_rtt

			try:
				if _object->_owner.callbacks.link_established != None:
						_object->_owner.callbacks.link_established(self)
			except Exception as e:
				RNS.log("Error occurred in external link establishment callback. The contained exception was: "+str(e), RNS.LOG_ERROR)

	except Exception as e:
		RNS.log("Error occurred while processing RTT packet, tearing down link. The contained exception was: "+str(e), RNS.LOG_ERROR)
		_object->_teardown()

def track_phy_stats(self, track):
	"""
	You can enable physical layer statistics on a per-link basis. If this is enabled,
	and the link is running over an interface that supports reporting physical layer
	statistics, you will be able to retrieve stats such as *RSSI*, *SNR* and physical
	*Link Quality* for the link.

	:param track: Whether or not to keep track of physical layer statistics. Value must be ``True`` or ``False``.
	"""
	if track:
		_object->___track_phy_stats = True
	else:
		_object->___track_phy_stats = False

def get_rssi(self):
	"""
	:returns: The physical layer *Received Signal Strength Indication* if available, otherwise ``None``. Physical layer statistics must be enabled on the link for this method to return a value.
	"""
	return _object->_rssi

def get_snr(self):
	"""
	:returns: The physical layer *Signal-to-Noise Ratio* if available, otherwise ``None``. Physical layer statistics must be enabled on the link for this method to return a value.
	"""
	return _object->_rssi

def get_q(self):
	"""
	:returns: The physical layer *Link Quality* if available, otherwise ``None``. Physical layer statistics must be enabled on the link for this method to return a value.
	"""
	return _object->_rssi

def get_establishment_rate(self):
	"""
	:returns: The data transfer rate at which the link establishment procedure ocurred, in bits per second.
	"""
	if _object->_establishment_rate != None:
		return _object->_establishment_rate*8
	else:
		return None

def get_salt(self):
	return _object->_link_id

def get_context(self):
	return None

def no_inbound_for(self):
	"""
	:returns: The time in seconds since last inbound packet on the link. This includes keepalive packets.
	"""
	activated_at = _object->_activated_at if _object->_activated_at != None else 0
	last_inbound = max(_object->_last_inbound, activated_at)
	return time.time() - last_inbound

def no_outbound_for(self):
	"""
	:returns: The time in seconds since last outbound packet on the link. This includes keepalive packets.
	"""
	return time.time() - _object->_last_outbound

def no_data_for(self):
	"""
	:returns: The time in seconds since payload data traversed the link. This excludes keepalive packets.
	"""
	return time.time() - _object->_last_data

def inactive_for(self):
	"""
	:returns: The time in seconds since activity on the link. This includes keepalive packets.
	"""
	return min(_object->_no_inbound_for(), _object->_no_outbound_for())

def get_remote_identity(self):
	"""
	:returns: The identity of the remote peer, if it is known. Calling this method will not query the remote initiator to reveal its identity. Returns ``None`` if the link initiator has not already independently called the ``identify(identity)`` method.
	"""
	return _object->___remote_identity

def had_outbound(self, is_keepalive=False):
	_object->_last_outbound = time.time()
	if not is_keepalive:
		_object->_last_data = _object->_last_outbound
*/
void Link::had_outbound() {
	assert(_object);
	_object->_last_outbound = RNS::Utilities::OS::ltime();
}
/*
def teardown(self):
	"""
	Closes the link and purges encryption keys. New keys will
	be used if a new link to the same destination is established.
	"""
	if _object->_status != Link.PENDING and _object->_status != Link.CLOSED:
		teardown_packet = RNS.Packet(self, _object->_link_id, context=RNS.Packet.LINKCLOSE)
		teardown_packet.send()
		_object->_had_outbound()
	_object->_status = Link.CLOSED
	if _object->_initiator:
		_object->_teardown_reason = Link.INITIATOR_CLOSED
	else:
		_object->_teardown_reason = Link.DESTINATION_CLOSED
	_object->_link_closed()

def teardown_packet(self, packet):
	try:
		plaintext = _object->_decrypt(packet.data)
		if plaintext == _object->_link_id:
			_object->_status = Link.CLOSED
			if _object->_initiator:
				_object->_teardown_reason = Link.DESTINATION_CLOSED
			else:
				_object->_teardown_reason = Link.INITIATOR_CLOSED
			_object->___update_phy_stats(packet)
			_object->_link_closed()
	except Exception as e:
		pass

def link_closed(self):
	for resource in _object->_incoming_resources:
		resource.cancel()
	for resource in _object->_outgoing_resources:
		resource.cancel()
	if _object->__channel:
		_object->__channel._shutdown()
		
	_object->_prv = None
	_object->_pub = None
	_object->_pub_bytes = None
	_object->_shared_key = None
	_object->_derived_key = None

	if _object->_destination != None:
		if _object->_destination.direction == RNS.Destination.IN:
			if self in _object->_destination.links:
				_object->_destination.links.remove(self)

	if _object->_callbacks.link_closed != None:
		try:
			_object->_callbacks.link_closed(self)
		except Exception as e:
			RNS.log("Error while executing link closed callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)


def start_watchdog(self):
	thread = threading.Thread(target=_object->___watchdog_job)
	thread.daemon = True
	thread.start()

def __watchdog_job(self):
	while not _object->_status == Link.CLOSED:
		while (_object->_watchdog_lock):
			rtt_wait = 0.025
			if hasattr(self, "rtt") and _object->_rtt:
				rtt_wait = _object->_rtt

			sleep(max(rtt_wait, 0.025))

		if not _object->_status == Link.CLOSED:
			# Link was initiated, but no response
			# from destination yet
			if _object->_status == Link.PENDING:
				next_check = _object->_request_time + _object->_establishment_timeout
				sleep_time = next_check - time.time()
				if time.time() >= _object->_request_time + _object->_establishment_timeout:
					RNS.log("Link establishment timed out", RNS.LOG_VERBOSE)
					_object->_status = Link.CLOSED
					_object->_teardown_reason = Link.TIMEOUT
					_object->_link_closed()
					sleep_time = 0.001

			elif _object->_status == Link.HANDSHAKE:
				next_check = _object->_request_time + _object->_establishment_timeout
				sleep_time = next_check - time.time()
				if time.time() >= _object->_request_time + _object->_establishment_timeout:
					_object->_status = Link.CLOSED
					_object->_teardown_reason = Link.TIMEOUT
					_object->_link_closed()
					sleep_time = 0.001

					if _object->_initiator:
						RNS.log("Timeout waiting for link request proof", RNS.LOG_DEBUG)
					else:
						RNS.log("Timeout waiting for RTT packet from link initiator", RNS.LOG_DEBUG)

			elif _object->_status == Link.ACTIVE:
				activated_at = _object->_activated_at if _object->_activated_at != None else 0
				last_inbound = max(max(_object->_last_inbound, _object->_last_proof), activated_at)

				if time.time() >= last_inbound + _object->_keepalive:
					if _object->_initiator:
						_object->_send_keepalive()

					if time.time() >= last_inbound + _object->_stale_time:
						sleep_time = _object->_rtt * _object->_keepalive_timeout_factor + Link.STALE_GRACE
						_object->_status = Link.STALE
					else:
						sleep_time = _object->_keepalive
				
				else:
					sleep_time = (last_inbound + _object->_keepalive) - time.time()

			elif _object->_status == Link.STALE:
				sleep_time = 0.001
				_object->_status = Link.CLOSED
				_object->_teardown_reason = Link.TIMEOUT
				_object->_link_closed()


			if sleep_time == 0:
				RNS.log("Warning! Link watchdog sleep time of 0!", RNS.LOG_ERROR)
			if sleep_time == None or sleep_time < 0:
				RNS.log("Timing error! Tearing down link "+str(self)+" now.", RNS.LOG_ERROR)
				_object->_teardown()
				sleep_time = 0.1

			sleep(sleep_time)


def __update_phy_stats(self, packet, query_shared = True):
	if _object->___track_phy_stats:
		if query_shared:
			reticulum = RNS.Reticulum.get_instance()
			if packet.rssi == None: packet.rssi = reticulum.get_packet_rssi(packet.packet_hash)
			if packet.snr  == None: packet.snr  = reticulum.get_packet_snr(packet.packet_hash)
			if packet.q    == None: packet.q    = reticulum.get_packet_q(packet.packet_hash)

		if packet.rssi != None:
			_object->_rssi = packet.rssi
		if packet.snr != None:
			_object->_snr = packet.snr
		if packet.q != None:
			_object->_q = packet.q

def send_keepalive(self):
	keepalive_packet = RNS.Packet(self, bytes([0xFF]), context=RNS.Packet.KEEPALIVE)
	keepalive_packet.send()
	_object->_had_outbound(is_keepalive = True)

def handle_request(self, request_id, unpacked_request):
	if _object->_status == Link.ACTIVE:
		requested_at = unpacked_request[0]
		path_hash    = unpacked_request[1]
		request_data = unpacked_request[2]

		if path_hash in _object->_destination.request_handlers:
			request_handler = _object->_destination.request_handlers[path_hash]
			path               = request_handler[0]
			response_generator = request_handler[1]
			allow              = request_handler[2]
			allowed_list       = request_handler[3]

			allowed = False
			if not allow == RNS.Destination.ALLOW_NONE:
				if allow == RNS.Destination.ALLOW_LIST:
					if _object->___remote_identity != None and _object->___remote_identity.hash in allowed_list:
						allowed = True
				elif allow == RNS.Destination.ALLOW_ALL:
					allowed = True

			if allowed:
				RNS.log("Handling request "+RNS.prettyhexrep(request_id)+" for: "+str(path), RNS.LOG_DEBUG)
				if len(inspect.signature(response_generator).parameters) == 5:
					response = response_generator(path, request_data, request_id, _object->___remote_identity, requested_at)
				elif len(inspect.signature(response_generator).parameters) == 6:
					response = response_generator(path, request_data, request_id, _object->_link_id, _object->___remote_identity, requested_at)
				else:
					raise TypeError("Invalid signature for response generator callback")

				if response != None:
					packed_response = umsgpack.packb([request_id, response])

					if len(packed_response) <= Link.MDU:
						RNS.Packet(self, packed_response, RNS.Packet.DATA, context = RNS.Packet.RESPONSE).send()
					else:
						response_resource = RNS.Resource(packed_response, self, request_id = request_id, is_response = True)
			else:
				identity_string = str(_object->_get_remote_identity()) if _object->_get_remote_identity() != None else "<Unknown>"
				RNS.log("Request "+RNS.prettyhexrep(request_id)+" from "+identity_string+" not allowed for: "+str(path), RNS.LOG_DEBUG)

def handle_response(self, request_id, response_data, response_size, response_transfer_size):
	if _object->_status == Link.ACTIVE:
		remove = None
		for pending_request in _object->_pending_requests:
			if pending_request.request_id == request_id:
				remove = pending_request
				try:
					pending_request.response_size = response_size
					if pending_request.response_transfer_size == None:
						pending_request.response_transfer_size = 0
					pending_request.response_transfer_size += response_transfer_size
					pending_request.response_received(response_data)
				except Exception as e:
					RNS.log("Error occurred while handling response. The contained exception was: "+str(e), RNS.LOG_ERROR)

				break

		if remove != None:
			if remove in _object->_pending_requests:
				_object->_pending_requests.remove(remove)

def request_resource_concluded(self, resource):
	if resource.status == RNS.Resource.COMPLETE:
		packed_request    = resource.data.read()
		unpacked_request  = umsgpack.unpackb(packed_request)
		request_id        = RNS.Identity.truncated_hash(packed_request)
		request_data      = unpacked_request

		_object->_handle_request(request_id, request_data)
	else:
		RNS.log("Incoming request resource failed with status: "+RNS.hexrep([resource.status]), RNS.LOG_DEBUG)

def response_resource_concluded(self, resource):
	if resource.status == RNS.Resource.COMPLETE:
		packed_response   = resource.data.read()
		unpacked_response = umsgpack.unpackb(packed_response)
		request_id        = unpacked_response[0]
		response_data     = unpacked_response[1]

		_object->_handle_response(request_id, response_data, resource.total_size, resource.size)
	else:
		RNS.log("Incoming response resource failed with status: "+RNS.hexrep([resource.status]), RNS.LOG_DEBUG)
		for pending_request in _object->_pending_requests:
			if pending_request.request_id == resource.request_id:
				pending_request.request_timed_out(None)

def get_channel(self):
	"""
	Get the ``Channel`` for this link.

	:return: ``Channel`` object
	"""
	if _object->__channel is None:
		_object->__channel = Channel(LinkChannelOutlet(self))
	return _object->__channel

def receive(self, packet):
	_object->_watchdog_lock = True
	if not _object->_status == Link.CLOSED and not (_object->_initiator and packet.context == RNS.Packet.KEEPALIVE and packet.data == bytes([0xFF])):
		if packet.receiving_interface != _object->_attached_interface:
			RNS.log("Link-associated packet received on unexpected interface! Someone might be trying to manipulate your communication!", RNS.LOG_ERROR)
		else:
			_object->_last_inbound = time.time()
			if packet.context != RNS.Packet.KEEPALIVE:
				_object->_last_data = _object->_last_inbound
			_object->_rx += 1
			_object->_rxbytes += len(packet.data)
			if _object->_status == Link.STALE:
				_object->_status = Link.ACTIVE

			if packet.packet_type == RNS.Packet.DATA:
				should_query = False
				if packet.context == RNS.Packet.NONE:
					plaintext = _object->_decrypt(packet.data)
					if plaintext != None:
						if _object->_callbacks.packet != None:
							thread = threading.Thread(target=_object->_callbacks.packet, args=(plaintext, packet))
							thread.daemon = True
							thread.start()
						
						if _object->_destination.proof_strategy == RNS.Destination.PROVE_ALL:
							packet.prove()
							should_query = True

						elif _object->_destination.proof_strategy == RNS.Destination.PROVE_APP:
							if _object->_destination.callbacks.proof_requested:
								try:
									if _object->_destination.callbacks.proof_requested(packet):
										packet.prove()
										should_query = True
								except Exception as e:
									RNS.log("Error while executing proof request callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)

						_object->___update_phy_stats(packet, query_shared=should_query)

				elif packet.context == RNS.Packet.LINKIDENTIFY:
					plaintext = _object->_decrypt(packet.data)
					if plaintext != None:
						if not _object->_initiator and len(plaintext) == RNS.Identity.KEYSIZE//8 + RNS.Identity.SIGLENGTH//8:
							public_key   = plaintext[:RNS.Identity.KEYSIZE//8]
							signed_data  = _object->_link_id+public_key
							signature    = plaintext[RNS.Identity.KEYSIZE//8:RNS.Identity.KEYSIZE//8+RNS.Identity.SIGLENGTH//8]
							identity     = RNS.Identity(create_keys=False)
							identity.load_public_key(public_key)

							if identity.validate(signature, signed_data):
								_object->___remote_identity = identity
								if _object->_callbacks.remote_identified != None:
									try:
										_object->_callbacks.remote_identified(self, _object->___remote_identity)
									except Exception as e:
										RNS.log("Error while executing remote identified callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
							
								_object->___update_phy_stats(packet, query_shared=True)

				elif packet.context == RNS.Packet.REQUEST:
					try:
						request_id = packet.getTruncatedHash()
						packed_request = _object->_decrypt(packet.data)
						if packed_request != None:
							unpacked_request = umsgpack.unpackb(packed_request)
							_object->_handle_request(request_id, unpacked_request)
							_object->___update_phy_stats(packet, query_shared=True)
					except Exception as e:
						RNS.log("Error occurred while handling request. The contained exception was: "+str(e), RNS.LOG_ERROR)

				elif packet.context == RNS.Packet.RESPONSE:
					try:
						packed_response = _object->_decrypt(packet.data)
						if packed_response != None:
							unpacked_response = umsgpack.unpackb(packed_response)
							request_id = unpacked_response[0]
							response_data = unpacked_response[1]
							transfer_size = len(umsgpack.packb(response_data))-2
							_object->_handle_response(request_id, response_data, transfer_size, transfer_size)
							_object->___update_phy_stats(packet, query_shared=True)
					except Exception as e:
						RNS.log("Error occurred while handling response. The contained exception was: "+str(e), RNS.LOG_ERROR)

				elif packet.context == RNS.Packet.LRRTT:
					if not _object->_initiator:
						_object->_rtt_packet(packet)
						_object->___update_phy_stats(packet, query_shared=True)

				elif packet.context == RNS.Packet.LINKCLOSE:
					_object->_teardown_packet(packet)
					_object->___update_phy_stats(packet, query_shared=True)

				elif packet.context == RNS.Packet.RESOURCE_ADV:
					packet.plaintext = _object->_decrypt(packet.data)
					if packet.plaintext != None:
						_object->___update_phy_stats(packet, query_shared=True)

						if RNS.ResourceAdvertisement.is_request(packet):
							RNS.Resource.accept(packet, callback=_object->_request_resource_concluded)
						elif RNS.ResourceAdvertisement.is_response(packet):
							request_id = RNS.ResourceAdvertisement.read_request_id(packet)
							for pending_request in _object->_pending_requests:
								if pending_request.request_id == request_id:
									response_resource = RNS.Resource.accept(packet, callback=_object->_response_resource_concluded, progress_callback=pending_request.response_resource_progress, request_id = request_id)
									if response_resource != None:
										if pending_request.response_size == None:
											pending_request.response_size = RNS.ResourceAdvertisement.read_size(packet)
										if pending_request.response_transfer_size == None:
											pending_request.response_transfer_size = 0
										pending_request.response_transfer_size += RNS.ResourceAdvertisement.read_transfer_size(packet)
										if pending_request.started_at == None:
											pending_request.started_at = time.time()
										pending_request.response_resource_progress(response_resource)

						elif _object->_resource_strategy == Link.ACCEPT_NONE:
							pass
						elif _object->_resource_strategy == Link.ACCEPT_APP:
							if _object->_callbacks.resource != None:
								try:
									resource_advertisement = RNS.ResourceAdvertisement.unpack(packet.plaintext)
									resource_advertisement.link = self
									if _object->_callbacks.resource(resource_advertisement):
										RNS.Resource.accept(packet, _object->_callbacks.resource_concluded)
								except Exception as e:
									RNS.log("Error while executing resource accept callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
						elif _object->_resource_strategy == Link.ACCEPT_ALL:
							RNS.Resource.accept(packet, _object->_callbacks.resource_concluded)

				elif packet.context == RNS.Packet.RESOURCE_REQ:
					plaintext = _object->_decrypt(packet.data)
					if plaintext != None:
						_object->___update_phy_stats(packet, query_shared=True)
						if ord(plaintext[:1]) == RNS.Resource.HASHMAP_IS_EXHAUSTED:
							resource_hash = plaintext[1+RNS.Resource.MAPHASH_LEN:RNS.Identity.HASHLENGTH//8+1+RNS.Resource.MAPHASH_LEN]
						else:
							resource_hash = plaintext[1:RNS.Identity.HASHLENGTH//8+1]

						for resource in _object->_outgoing_resources:
							if resource.hash == resource_hash:
								# We need to check that this request has not been
								# received before in order to avoid sequencing errors.
								if not packet.packet_hash in resource.req_hashlist:
									resource.req_hashlist.append(packet.packet_hash)
									resource.request(plaintext)

				elif packet.context == RNS.Packet.RESOURCE_HMU:
					plaintext = _object->_decrypt(packet.data)
					if plaintext != None:
						_object->___update_phy_stats(packet, query_shared=True)
						resource_hash = plaintext[:RNS.Identity.HASHLENGTH//8]
						for resource in _object->_incoming_resources:
							if resource_hash == resource.hash:
								resource.hashmap_update_packet(plaintext)

				elif packet.context == RNS.Packet.RESOURCE_ICL:
					plaintext = _object->_decrypt(packet.data)
					if plaintext != None:
						_object->___update_phy_stats(packet)
						resource_hash = plaintext[:RNS.Identity.HASHLENGTH//8]
						for resource in _object->_incoming_resources:
							if resource_hash == resource.hash:
								resource.cancel()

				elif packet.context == RNS.Packet.KEEPALIVE:
					if not _object->_initiator and packet.data == bytes([0xFF]):
						keepalive_packet = RNS.Packet(self, bytes([0xFE]), context=RNS.Packet.KEEPALIVE)
						keepalive_packet.send()
						_object->_had_outbound(is_keepalive = True)


				# TODO: find the most efficient way to allow multiple
				# transfers at the same time, sending resource hash on
				# each packet is a huge overhead. Probably some kind
				# of hash -> sequence map
				elif packet.context == RNS.Packet.RESOURCE:
					for resource in _object->_incoming_resources:
						resource.receive_part(packet)
						_object->___update_phy_stats(packet)

				elif packet.context == RNS.Packet.CHANNEL:
					if not _object->__channel:
						RNS.log(f"Channel data received without open channel", RNS.LOG_DEBUG)
					else:
						packet.prove()
						plaintext = _object->_decrypt(packet.data)
						if plaintext != None:
							_object->___update_phy_stats(packet)
							_object->__channel._receive(plaintext)

			elif packet.packet_type == RNS.Packet.PROOF:
				if packet.context == RNS.Packet.RESOURCE_PRF:
					resource_hash = packet.data[0:RNS.Identity.HASHLENGTH//8]
					for resource in _object->_outgoing_resources:
						if resource_hash == resource.hash:
							resource.validate_proof(packet.data)
							_object->___update_phy_stats(packet, query_shared=True)

	_object->_watchdog_lock = False


def encrypt(self, plaintext):
	try:
		if not _object->_fernet:
			try:
				_object->_fernet = Fernet(_object->_derived_key)
			except Exception as e:
				RNS.log("Could not instantiate Fernet while performin encryption on link "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
				raise e

		return _object->_fernet.encrypt(plaintext)

	except Exception as e:
		RNS.log("Encryption on link "+str(self)+" failed. The contained exception was: "+str(e), RNS.LOG_ERROR)
		raise e


def decrypt(self, ciphertext):
	try:
		if not _object->_fernet:
			_object->_fernet = Fernet(_object->_derived_key)
			
		return _object->_fernet.decrypt(ciphertext)

	except Exception as e:
		RNS.log("Decryption failed on link "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
		return None


def sign(self, message):
	return _object->_sig_prv.sign(message)

def validate(self, signature, message):
	try:
		_object->_peer_sig_pub.verify(signature, message)
		return True
	except Exception as e:
		return False

def set_link_established_callback(self, callback):
	_object->_callbacks.link_established = callback

def set_link_closed_callback(self, callback):
	"""
	Registers a function to be called when a link has been
	torn down.

	:param callback: A function or method with the signature *callback(link)* to be called.
	"""
	_object->_callbacks.link_closed = callback

def set_packet_callback(self, callback):
	"""
	Registers a function to be called when a packet has been
	received over this link.

	:param callback: A function or method with the signature *callback(message, packet)* to be called.
	"""
	_object->_callbacks.packet = callback

def set_resource_callback(self, callback):
	"""
	Registers a function to be called when a resource has been
	advertised over this link. If the function returns *True*
	the resource will be accepted. If it returns *False* it will
	be ignored.

	:param callback: A function or method with the signature *callback(resource)* to be called. Please note that only the basic information of the resource is available at this time, such as *get_transfer_size()*, *get_data_size()*, *get_parts()* and *is_compressed()*.
	"""
	_object->_callbacks.resource = callback

def set_resource_started_callback(self, callback):
	"""
	Registers a function to be called when a resource has begun
	transferring over this link.

	:param callback: A function or method with the signature *callback(resource)* to be called.
	"""
	_object->_callbacks.resource_started = callback

def set_resource_concluded_callback(self, callback):
	"""
	Registers a function to be called when a resource has concluded
	transferring over this link.

	:param callback: A function or method with the signature *callback(resource)* to be called.
	"""
	_object->_callbacks.resource_concluded = callback

def set_remote_identified_callback(self, callback):
	"""
	Registers a function to be called when an initiating peer has
	identified over this link.

	:param callback: A function or method with the signature *callback(link, identity)* to be called.
	"""
	_object->_callbacks.remote_identified = callback

def resource_concluded(self, resource):
	if resource in _object->_incoming_resources:
		_object->_incoming_resources.remove(resource)
	if resource in _object->_outgoing_resources:
		_object->_outgoing_resources.remove(resource)

def set_resource_strategy(self, resource_strategy):
	"""
	Sets the resource strategy for the link.

	:param resource_strategy: One of ``RNS.Link.ACCEPT_NONE``, ``RNS.Link.ACCEPT_ALL`` or ``RNS.Link.ACCEPT_APP``. If ``RNS.Link.ACCEPT_APP`` is set, the `resource_callback` will be called to determine whether the resource should be accepted or not.
	:raises: *TypeError* if the resource strategy is unsupported.
	"""
	if not resource_strategy in Link.resource_strategies:
		raise TypeError("Unsupported resource strategy")
	else:
		_object->_resource_strategy = resource_strategy

def register_outgoing_resource(self, resource):
	_object->_outgoing_resources.append(resource)

def register_incoming_resource(self, resource):
	_object->_incoming_resources.append(resource)

def has_incoming_resource(self, resource):
	for incoming_resource in _object->_incoming_resources:
		if incoming_resource.hash == resource.hash:
			return True

	return False

def cancel_outgoing_resource(self, resource):
	if resource in _object->_outgoing_resources:
		_object->_outgoing_resources.remove(resource)
	else:
		RNS.log("Attempt to cancel a non-existing outgoing resource", RNS.LOG_ERROR)

def cancel_incoming_resource(self, resource):
	if resource in _object->_incoming_resources:
		_object->_incoming_resources.remove(resource)
	else:
		RNS.log("Attempt to cancel a non-existing incoming resource", RNS.LOG_ERROR)

def ready_for_new_resource(self):
	if len(_object->_outgoing_resources) > 0:
		return False
	else:
		return True

def __str__(self):
	return RNS.prettyhexrep(_object->_link_id)


class RequestReceipt():
"""
An instance of this class is returned by the ``request`` method of ``RNS.Link``
instances. It should never be instantiated manually. It provides methods to
check status, response time and response data when the request concludes.
"""

FAILED    = 0x00
SENT      = 0x01
DELIVERED = 0x02
RECEIVING = 0x03
READY     = 0x04

def __init__(self, link, packet_receipt = None, resource = None, response_callback = None, failed_callback = None, progress_callback = None, timeout = None, request_size = None):
	_object->_packet_receipt = packet_receipt
	_object->_resource = resource
	_object->_started_at = None

	if _object->_packet_receipt != None:
		_object->_hash = packet_receipt.truncated_hash
		_object->_packet_receipt.set_timeout_callback(_object->_request_timed_out)
		_object->_started_at = time.time()

	elif _object->_resource != None:
		_object->_hash = resource.request_id
		resource.set_callback(_object->_request_resource_concluded)
	
	_object->_link                   = link
	_object->_request_id             = _object->_hash
	_object->_request_size           = request_size

	_object->_response               = None
	_object->_response_transfer_size = None
	_object->_response_size          = None
	_object->_status                 = RequestReceipt.SENT
	_object->_sent_at                = time.time()
	_object->_progress               = 0
	_object->_concluded_at           = None
	_object->_response_concluded_at  = None

	if timeout != None:
		_object->_timeout        = timeout
	else:
		raise ValueError("No timeout specified for request receipt")

	_object->_callbacks          = RequestReceiptCallbacks()
	_object->_callbacks.response = response_callback
	_object->_callbacks.failed   = failed_callback
	_object->_callbacks.progress = progress_callback

	_object->_link.pending_requests.append(self)


def request_resource_concluded(self, resource):
	if resource.status == RNS.Resource.COMPLETE:
		RNS.log("Request "+RNS.prettyhexrep(_object->_request_id)+" successfully sent as resource.", RNS.LOG_DEBUG)
		if _object->_started_at == None:
			_object->_started_at = time.time()
		_object->_status = RequestReceipt.DELIVERED
		_object->___resource_response_timeout = time.time()+_object->_timeout
		response_timeout_thread = threading.Thread(target=_object->___response_timeout_job)
		response_timeout_thread.daemon = True
		response_timeout_thread.start()
	else:
		RNS.log("Sending request "+RNS.prettyhexrep(_object->_request_id)+" as resource failed with status: "+RNS.hexrep([resource.status]), RNS.LOG_DEBUG)
		_object->_status = RequestReceipt.FAILED
		_object->_concluded_at = time.time()
		_object->_link.pending_requests.remove(self)

		if _object->_callbacks.failed != None:
			try:
				_object->_callbacks.failed(self)
			except Exception as e:
				RNS.log("Error while executing request failed callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)


def __response_timeout_job(self):
	while _object->_status == RequestReceipt.DELIVERED:
		now = time.time()
		if now > _object->___resource_response_timeout:
			_object->_request_timed_out(None)

		time.sleep(0.1)


def request_timed_out(self, packet_receipt):
	_object->_status = RequestReceipt.FAILED
	_object->_concluded_at = time.time()
	_object->_link.pending_requests.remove(self)

	if _object->_callbacks.failed != None:
		try:
			_object->_callbacks.failed(self)
		except Exception as e:
			RNS.log("Error while executing request timed out callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)


def response_resource_progress(self, resource):
	if resource != None:
		if not _object->_status == RequestReceipt.FAILED:
			_object->_status = RequestReceipt.RECEIVING
			if _object->_packet_receipt != None:
				if _object->_packet_receipt.status != RNS.PacketReceipt.DELIVERED:
					_object->_packet_receipt.status = RNS.PacketReceipt.DELIVERED
					_object->_packet_receipt.proved = True
					_object->_packet_receipt.concluded_at = time.time()
					if _object->_packet_receipt.callbacks.delivery != None:
						_object->_packet_receipt.callbacks.delivery(_object->_packet_receipt)

			_object->_progress = resource.get_progress()
			
			if _object->_callbacks.progress != None:
				try:
					_object->_callbacks.progress(self)
				except Exception as e:
					RNS.log("Error while executing response progress callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
		else:
			resource.cancel()


def response_received(self, response):
	if not _object->_status == RequestReceipt.FAILED:
		_object->_progress = 1.0
		_object->_response = response
		_object->_status = RequestReceipt.READY
		_object->_response_concluded_at = time.time()

		if _object->_packet_receipt != None:
			_object->_packet_receipt.status = RNS.PacketReceipt.DELIVERED
			_object->_packet_receipt.proved = True
			_object->_packet_receipt.concluded_at = time.time()
			if _object->_packet_receipt.callbacks.delivery != None:
				_object->_packet_receipt.callbacks.delivery(_object->_packet_receipt)

		if _object->_callbacks.progress != None:
			try:
				_object->_callbacks.progress(self)
			except Exception as e:
				RNS.log("Error while executing response progress callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)

		if _object->_callbacks.response != None:
			try:
				_object->_callbacks.response(self)
			except Exception as e:
				RNS.log("Error while executing response received callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)

def get_request_id(self):
	"""
	:returns: The request ID as *bytes*.
	"""
	return _object->_request_id

def get_status(self):
	"""
	:returns: The current status of the request, one of ``RNS.RequestReceipt.FAILED``, ``RNS.RequestReceipt.SENT``, ``RNS.RequestReceipt.DELIVERED``, ``RNS.RequestReceipt.READY``.
	"""
	return _object->_status

def get_progress(self):
	"""
	:returns: The progress of a response being received as a *float* between 0.0 and 1.0.
	"""
	return _object->_progress

def get_response(self):
	"""
	:returns: The response as *bytes* if it is ready, otherwise *None*.
	"""
	if _object->_status == RequestReceipt.READY:
		return _object->_response
	else:
		return None

def get_response_time(self):
	"""
	:returns: The response time of the request in seconds.
	"""
	if _object->_status == RequestReceipt.READY:
		return _object->_response_concluded_at - _object->_started_at
	else:
		return None

*/