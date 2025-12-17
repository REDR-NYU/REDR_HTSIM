
#include "uec_mp.h"
#include "config.h"

#include <iostream>


UecMpOblivious::UecMpOblivious(uint16_t no_of_paths,
                               bool debug)
    : UecMultipath(debug),
      _no_of_paths(no_of_paths),
      _current_ev_index(0)
      {

    _path_random = rand() % UINT16_MAX;  // random upper bits of EV
    _path_xor = rand() % _no_of_paths;

    if (_debug)
        cout << "Multipath"
            << " Oblivious"
            << " _no_of_paths " << _no_of_paths
            << " _path_random " << _path_random
            << " _path_xor " << _path_xor
            << endl;
}

void UecMpOblivious::processEv(uint16_t path_id, PathFeedback feedback) {
    return;
}

uint16_t UecMpOblivious::nextEntropy(uint64_t seq_sent, uint64_t cur_cwnd_in_pkts) {
    // _no_of_paths must be a power of 2
    uint16_t mask = _no_of_paths - 1;
    uint16_t entropy = (_current_ev_index ^ _path_xor) & mask;

    // set things for next time
    _current_ev_index++;
    if (_current_ev_index == _no_of_paths) {
        _current_ev_index = 0;
        _path_xor = rand() & mask;
    }

    entropy |= _path_random ^ (_path_random & mask);  // set upper bits
    return entropy;
}


UecMpBitmap::UecMpBitmap(uint16_t no_of_paths, bool debug)
    : UecMultipath(debug),
      _no_of_paths(no_of_paths),
      _current_ev_index(0),
      _ev_skip_bitmap(),
      _ev_skip_count(0)
      {

    _max_penalty = 15;

    _path_random = rand() % 0xffff;  // random upper bits of EV
    _path_xor = rand() % _no_of_paths;

    _ev_skip_bitmap.resize(_no_of_paths);
    for (uint32_t i = 0; i < _no_of_paths; i++) {
        _ev_skip_bitmap[i] = 0;
    }

    if (_debug)
        cout << "Multipath"
            << " Bitmap"
            << " _no_of_paths " << _no_of_paths
            << " _path_random " << _path_random
            << " _path_xor " << _path_xor
            << " _max_penalty " << (uint32_t)_max_penalty
            << endl;
}

void UecMpBitmap::processEv(uint16_t path_id, PathFeedback feedback) {
    // _no_of_paths must be a power of 2
    uint16_t mask = _no_of_paths - 1;
    path_id &= mask;  // only take the relevant bits for an index

    if (feedback != PathFeedback::PATH_GOOD && !_ev_skip_bitmap[path_id])
        _ev_skip_count++;

    uint8_t penalty = 0;

    if (feedback == PathFeedback::PATH_ECN)
        penalty = 1;
    else if (feedback == PathFeedback::PATH_NACK)
        penalty = 4;
    else if (feedback == PathFeedback::PATH_TIMEOUT)
        penalty = _max_penalty;

    _ev_skip_bitmap[path_id] += penalty;
    if (_ev_skip_bitmap[path_id] > _max_penalty) {
        _ev_skip_bitmap[path_id] = _max_penalty;
    }
}

uint16_t UecMpBitmap::nextEntropy(uint64_t seq_sent, uint64_t cur_cwnd_in_pkts) {
    // _no_of_paths must be a power of 2
    uint16_t mask = _no_of_paths - 1;
    uint16_t entropy = (_current_ev_index ^ _path_xor) & mask;
    bool flag = false;
    int counter = 0;
    while (_ev_skip_bitmap[entropy] > 0) {
        if (flag == false){
            _ev_skip_bitmap[entropy]--;
            if (!_ev_skip_bitmap[entropy]){
                assert(_ev_skip_count>0);
                _ev_skip_count--;
            }
        }

        flag = true;
        counter ++;
        if (counter > _no_of_paths){
            break;
        }
        _current_ev_index++;
        if (_current_ev_index == _no_of_paths) {
            _current_ev_index = 0;
            _path_xor = rand() & mask;
        }
        entropy = (_current_ev_index ^ _path_xor) & mask;
    }

    // set things for next time
    _current_ev_index++;
    if (_current_ev_index == _no_of_paths) {
        _current_ev_index = 0;
        _path_xor = rand() & mask;
    }

    entropy |= _path_random ^ (_path_random & mask);  // set upper bits
    return entropy;
}

UecMpReps::UecMpReps(uint16_t no_of_paths, bool debug, bool is_trimming_enabled)
    : UecMultipath(debug),
      _no_of_paths(no_of_paths),
      _crt_path(0),
      _is_trimming_enabled(is_trimming_enabled) {

    circular_buffer_reps = new CircularBufferREPS<uint16_t>(CircularBufferREPS<uint16_t>::repsBufferSize);

    if (_debug)
        cout << "Multipath"
            << " REPS"
            << " _no_of_paths " << _no_of_paths
            << endl;
}

void UecMpReps::processEv(uint16_t path_id, PathFeedback feedback) {

    if ((feedback == PATH_TIMEOUT) && !circular_buffer_reps->isFrozenMode() && circular_buffer_reps->explore_counter == 0) {
        if (_is_trimming_enabled) { // If we have trimming enabled
            circular_buffer_reps->setFrozenMode(true);
            circular_buffer_reps->can_exit_frozen_mode = EventList::getTheEventList().now() +  circular_buffer_reps->exit_freeze_after;
        } else {
            cout << timeAsUs(EventList::getTheEventList().now()) << "REPS currently requires trimming in this implementation." << endl;
            exit(EXIT_FAILURE); // If we reach this point, it means we are trying to enter freezing mode without trimming enabled.
        } // In this version of REPS, we do not enter freezing mode without trimming enabled. Check the REPS paper to implement it also without trimming.
    }

    if (circular_buffer_reps->isFrozenMode() && EventList::getTheEventList().now() > circular_buffer_reps->can_exit_frozen_mode) {
        circular_buffer_reps->setFrozenMode(false);
        circular_buffer_reps->resetBuffer();
        circular_buffer_reps->explore_counter = 16;
    }

    if ((feedback == PATH_GOOD) && !circular_buffer_reps->isFrozenMode()) {
        circular_buffer_reps->add(path_id);
    } else if (circular_buffer_reps->isFrozenMode() && (feedback == PATH_GOOD)) {
        circular_buffer_reps->add(path_id);
    }
}

uint16_t UecMpReps::nextEntropy(uint64_t seq_sent, uint64_t cur_cwnd_in_pkts) {
    if (circular_buffer_reps->explore_counter > 0) {
        circular_buffer_reps->explore_counter--;
        return rand() % _no_of_paths;
    }

    if (circular_buffer_reps->isFrozenMode()) {
        if (circular_buffer_reps->isEmpty()) {
            return rand() % _no_of_paths;
        } else {
            return circular_buffer_reps->remove_frozen();
        }
    } else {
        if (circular_buffer_reps->isEmpty() || circular_buffer_reps->getNumberFreshEntropies() == 0) {
            return _crt_path = rand() % _no_of_paths;
        } else {
            return circular_buffer_reps->remove_earliest_fresh();
        }
    }
}


UecMpRepsLegacy::UecMpRepsLegacy(uint16_t no_of_paths, bool debug)
    : UecMultipath(debug),
      _no_of_paths(no_of_paths),
      _crt_path(0) {

    if (_debug)
        cout << "Multipath"
            << " REPS"
            << " _no_of_paths " << _no_of_paths
            << endl;
}

void UecMpRepsLegacy::processEv(uint16_t path_id, PathFeedback feedback) {
    if (feedback == PATH_GOOD){
        _next_pathid.push_back(path_id);
        if (_debug){
            cout << timeAsUs(EventList::getTheEventList().now()) << " " << _debug_tag << " REPS Add " << path_id << " " << _next_pathid.size() << endl;
        }
    }
}

uint16_t UecMpRepsLegacy::nextEntropy(uint64_t seq_sent, uint64_t cur_cwnd_in_pkts) {
    if (seq_sent < min(cur_cwnd_in_pkts, (uint64_t)_no_of_paths)) {
        _crt_path++;
        if (_crt_path == _no_of_paths) {
            _crt_path = 0;
        }

        if (_debug) 
            cout << timeAsUs(EventList::getTheEventList().now()) << " " << _debug_tag << " REPS FirstWindow " << _crt_path << endl;

    } else {
        if (_next_pathid.empty()) {
            assert(_no_of_paths > 0);
		    _crt_path = random() % _no_of_paths;

            if (_debug) 
                cout << timeAsUs(EventList::getTheEventList().now()) << " " << _debug_tag << " REPS Steady " << _crt_path << endl;

        } else {
            _crt_path = _next_pathid.front();
            _next_pathid.pop_front();

            if (_debug) 
                cout << timeAsUs(EventList::getTheEventList().now()) << " " << _debug_tag << " REPS Recycle " << _crt_path << " " << _next_pathid.size() << endl;

        }
    }
    return _crt_path;
}

optional<uint16_t> UecMpRepsLegacy::nextEntropyRecycle() {
    if (_next_pathid.empty()) {
        return {};
    } else {
        _crt_path = _next_pathid.front();
        _next_pathid.pop_front();

        if (_debug) 
            cout << timeAsUs(EventList::getTheEventList().now()) << " " << _debug_tag << " MIXED Recycle " << _crt_path << " " << _next_pathid.size() << endl;
        return { _crt_path };
    }
}


UecMpMixed::UecMpMixed(uint16_t no_of_paths, bool debug)
    : UecMultipath(debug),
      _bitmap(UecMpBitmap(no_of_paths, debug)),
      _reps_legacy(UecMpRepsLegacy(no_of_paths, debug))
      {
}

void UecMpMixed::set_debug_tag(string debug_tag) {
    _bitmap.set_debug_tag(debug_tag);
    _reps_legacy.set_debug_tag(debug_tag);
}

void UecMpMixed::processEv(uint16_t path_id, PathFeedback feedback) {
    _bitmap.processEv(path_id, feedback);
    _reps_legacy.processEv(path_id, feedback);
}

uint16_t UecMpMixed::nextEntropy(uint64_t seq_sent, uint64_t cur_cwnd_in_pkts) {
    auto reps_val = _reps_legacy.nextEntropyRecycle();
    if (reps_val.has_value()) {
        return reps_val.value();
    } else {
        return _bitmap.nextEntropy(seq_sent, cur_cwnd_in_pkts);
    }
}

UecMpEcmp::UecMpEcmp(uint16_t no_of_paths, bool debug)
    : UecMultipath(debug),
      _crt_path(0) {
    if (_debug)
        cout << "Multipath"
            << " ECMP"
            << " _no_of_paths " << no_of_paths
            << endl;
    _crt_path = rand() % no_of_paths;
}

void UecMpEcmp::processEv(uint16_t path_id, PathFeedback feedback) {
    // No OP in ECMP
    return;
}

uint16_t UecMpEcmp::nextEntropy(uint64_t seq_sent, uint64_t cur_cwnd_in_pkts) {
    // Always same path for a given flow in ECMP
    return _crt_path;
}

const simtime_picosec UecMpRedr::TIMEOUT = timeFromUs((uint32_t)1000);

UecMpRedr::UecMpRedr(uint16_t no_of_paths, bool debug)
    : UecMultipath(debug),
      _no_of_paths(no_of_paths),
      _head(0),
      _validEVs(0),
      _exploreCounter(16),  // Start with initial exploration phase
      _deflected_packets_total(0),
      _deflected_packets_acked(0) {
    
    _EVbuffer.resize(REPS_BUFFER_SIZE);
    
    if (_debug)
        cout << "Multipath"
            << " REDR"
            << " _no_of_paths " << _no_of_paths
            << " REPS_BUFFER_SIZE " << REPS_BUFFER_SIZE
            << endl;
}

void UecMpRedr::processEv(uint16_t path_id, PathFeedback feedback) {
    // Standard interface - convert to REDR-specific call
    // For REDR, we use onAck which is called separately from UecSrc
    // This is a fallback that shouldn't normally be called for REDR
    // but we implement it for interface compatibility
    bool ecn = (feedback == PATH_ECN);
    bool deflected = false;  // We don't have this info here, will be set via onAck
    onAck(path_id, ecn, deflected);
}

void UecMpRedr::onAck(uint16_t ev, bool ecn, bool deflected) {
    processAckInternal(ev, ecn, deflected);
}

void UecMpRedr::processAckInternal(uint16_t ev, bool ecn, bool deflected) {
    // Algorithm: onAck procedure
    if (_debug) {
        cout << "[REDR onAck] t=" << timeAsUs(EventList::getTheEventList().now()) 
             << " ev=" << ev << " ecn=" << ecn << " deflected=" << deflected
             << " head=" << _head << " validEVs=" << _validEVs << endl;
    }
    
    if (ecn) {
        if (_debug) {
            cout << "[REDR onAck] ECN detected, skipping ACK processing" << endl;
        }
        return;  // If ECN is set, return early (don't process this ACK)
    }
    
    _EVbuffer[_head].cachedEV = ev;
    
    if (deflected) {
        _deflected_packets_total++;
        _deflected_packets_acked++;  // This ACK means the deflected packet was successfully received
        _EVbuffer[_head].isFrozen = true;
        _EVbuffer[_head].unfreeze = EventList::getTheEventList().now() + TIMEOUT;
        // Don't mark as valid or increment _validEVs for deflected packets
        // Just advance head and return
        if (_debug) {
            cout << "[REDR onAck] PACKET DEFLECTED! ev=" << ev 
                 << " - freezing path, unfreeze at t=" << timeAsUs(_EVbuffer[_head].unfreeze)
                 << " (timeout=" << timeAsUs(TIMEOUT) << ")" << endl;
        }
        _head = (_head + 1) % REPS_BUFFER_SIZE;
        return;
    }
    
    // Not deflected - mark as valid and advance head
    if (!_EVbuffer[_head].isValid) {
        _validEVs++;
        if (_debug) {
            cout << "[REDR onAck] New valid EV added: ev=" << ev 
                 << " validEVs now=" << _validEVs << endl;
        }
    } else {
        if (_debug) {
            cout << "[REDR onAck] Updating existing valid EV: ev=" << ev << endl;
        }
    }
    
    _EVbuffer[_head].isValid = true;
    _EVbuffer[_head].isFrozen = false;  // Clear frozen state for non-deflected
    _head = (_head + 1) % REPS_BUFFER_SIZE;
    
    if (_debug) {
        cout << "[REDR onAck] Successfully processed ACK, head now=" << _head << endl;
    }
}

uint16_t UecMpRedr::getNextEV() {
    // Algorithm: getNextEV procedure
    uint32_t offset = 0;
    
    if (_validEVs > 0) {
        offset = (_head - _validEVs + REPS_BUFFER_SIZE) % REPS_BUFFER_SIZE;
        uint16_t old_ev = _EVbuffer[offset].cachedEV;
        bool was_frozen = _EVbuffer[offset].isFrozen;
        _EVbuffer[offset].isValid = false;
        _validEVs--;
        
        if (_debug) {
            cout << "[REDR getNextEV] Retrieved ev=" << old_ev 
                 << " from offset=" << offset << " (was_frozen=" << was_frozen << ")"
                 << " validEVs now=" << _validEVs << endl;
        }
        
        if (_EVbuffer[offset].isFrozen) {
            simtime_picosec now = EventList::getTheEventList().now();
            if (_EVbuffer[offset].unfreeze > now) {
                // Still frozen, recursively call to get next
                if (_debug) {
                    cout << "[REDR getNextEV] Path still frozen (unfreeze at " 
                         << timeAsUs(_EVbuffer[offset].unfreeze) << "), getting next EV" << endl;
                }
                return getNextEV();
            } else {
                _EVbuffer[offset].clonePacket = true;
                if (_debug) {
                    cout << "[REDR getNextEV] Path unfrozen, will clone packet for ev=" << old_ev << endl;
                }
            }
        }
        
        return old_ev;
    }
    
    if (_debug) {
        cout << "[REDR getNextEV] No valid EVs available!" << endl;
    }
    
    return 0;  // Should not happen if called correctly
}

uint16_t UecMpRedr::nextEntropy(uint64_t seq_sent, uint64_t cur_cwnd_in_pkts) {
    // Algorithm: onSend procedure
    // Explore initially or if buffer is empty
    if (_exploreCounter > 0) {
        uint16_t explore_ev = rand() % EVS_SIZE;
        _exploreCounter--;
        if (_debug) {
            cout << "[REDR nextEntropy] EXPLORING: ev=" << explore_ev 
                 << " (exploreCounter=" << _exploreCounter << " remaining)" << endl;
        }
        return explore_ev;
    }
    
    // If buffer is empty or no valid EVs, explore
    if (_validEVs == 0) {
        uint16_t explore_ev = rand() % EVS_SIZE;
        if (_debug) {
            cout << "[REDR nextEntropy] Buffer empty, EXPLORING: ev=" << explore_ev 
                 << " validEVs=" << _validEVs << endl;
        }
        return explore_ev;
    }
    
    // Use the buffer - get next EV from circular buffer
    uint16_t ev = getNextEV();
    if (_debug) {
        cout << "[REDR nextEntropy] Using buffer: ev=" << ev 
             << " seq=" << seq_sent << " cwnd=" << cur_cwnd_in_pkts << endl;
    }
    return ev;
}

void UecMpRedr::printStats() const {
    cout << "\n========== REDR Statistics ==========" << endl;
    cout << "Total deflected packets (ACKed): " << _deflected_packets_total << endl;
    cout << "Deflected packets successfully ACKed: " << _deflected_packets_acked << endl;
    if (_deflected_packets_total > 0) {
        // All deflected packets we track are successfully ACKed (we only track them when ACKed)
        cout << "Deflection ACK success rate: 100.0%" << endl;
    } else {
        cout << "No deflected packets were ACKed" << endl;
    }
    cout << "Valid EVs in buffer: " << _validEVs << endl;
    cout << "=====================================\n" << endl;
}