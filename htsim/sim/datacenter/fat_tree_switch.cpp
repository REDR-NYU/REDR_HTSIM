// -*- c-basic-offset: 4; indent-tabs-mode: nil -*-
#include "fat_tree_switch.h"
#include "routetable.h"
#include "fat_tree_topology.h"
#include "callback_pipe.h"
#include "pipe.h"
#include "queue_lossless.h"
#include "queue_lossless_output.h"
#include "queue_lossless_input.h"
#include "uecpacket.h"

unordered_map<BaseQueue*,uint32_t> FatTreeSwitch::_port_flow_counts;

FatTreeSwitch::FatTreeSwitch(EventList& eventlist, string s, switch_type t, uint32_t id,simtime_picosec delay, FatTreeTopology* ft): Switch(eventlist, s) {
    _id = id;
    _type = t;
    _pipe = new CallbackPipe(delay,eventlist, this);
    _uproutes = NULL;
    _ft = ft;
    _crt_route = 0;
    _hash_salt = random();
    _last_choice = eventlist.now();
    _fib = new RouteTable();
}

FatTreeSwitch::~FatTreeSwitch() {
    delete _pipe;
    delete _fib;
}

void FatTreeSwitch::receivePacket(Packet& pkt){
    if (pkt.type()==ETH_PAUSE){
        EthPausePacket* p = (EthPausePacket*)&pkt;
        //I must be in lossless mode!
        //find the egress queue that should process this, and pass it over for processing. 
        for (size_t i = 0;i < _ports.size();i++){
            LosslessQueue* q = (LosslessQueue*)_ports.at(i);
            if (q->getRemoteEndpoint() && ((Switch*)q->getRemoteEndpoint())->getID() == p->senderID()){
                q->receivePacket(pkt);
                break;
            }
        }
        
        return;
    }

    if (_packets.find(&pkt)==_packets.end()){
        //ingress pipeline processing.

        _packets[&pkt] = true;

        // For REDR rerouting, get the ingress queue from the packet
        // LosslessInputQueue sets this before calling receivePacket
        BaseQueue* ingress_for_routing = NULL;
        if (_enable_redr && (pkt.type() == UECDATA || pkt.type() == UECACK || 
                             pkt.type() == UECNACK || pkt.type() == UECPULL || 
                             pkt.type() == UECRTS) && pkt._ingressqueue) {
            // Since FatTreeSwitch is a friend of Packet, we can access _ingressqueue directly
            ingress_for_routing = dynamic_cast<BaseQueue*>(pkt._ingressqueue);
        }
        const Route * nh = getNextHop(pkt, ingress_for_routing);
        if (!nh) {
            // No route available - drop the packet
            _packets.erase(&pkt);
            pkt.flow().logTraffic(pkt, *this, TrafficLogger::PKT_DROP);
            pkt.free();
            return;
        }
        //set next hop which is peer switch.
        // Note: Don't clear ingress queue here - LosslessOutputQueue needs it and will clear it
        pkt.set_route(*nh);

        //emulate the switching latency between ingress and packet arriving at the egress queue.
        _pipe->receivePacket(pkt); 
    }
    else {
        _packets.erase(&pkt);
        
        //egress queue processing.
        //cout << "Switch type " << _type <<  " id " << _id << " pkt dst " << pkt.dst() << " dir " << pkt.get_direction() << endl;
        pkt.sendOn();
    }
};

void FatTreeSwitch::addHostPort(int addr, int flowid, PacketSink* transport_port){
    Route* rt = new Route();
    rt->push_back(_ft->queues_nlp_ns[_ft->cfg().HOST_POD_SWITCH(addr)][addr][0]);
    rt->push_back(_ft->pipes_nlp_ns[_ft->cfg().HOST_POD_SWITCH(addr)][addr][0]);
    rt->push_back(transport_port);
    _fib->addHostRoute(addr,rt,flowid);
}

uint32_t mhash(uint32_t x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

uint32_t FatTreeSwitch::adaptive_route_p2c(vector<FibEntry*>* ecmp_set, int8_t (*cmp)(FibEntry*,FibEntry*)){
    uint32_t choice = 0, min = UINT32_MAX;
    uint32_t start, i = 0;
    static const uint16_t nr_choices = 2;
    
    do {
        start = random()%ecmp_set->size();

        Route * r= (*ecmp_set)[start]->getEgressPort();
        assert(r && r->size()>1);
        BaseQueue* q = (BaseQueue*)(r->at(0));
        assert(q);
        if (q->queuesize()<min){
            choice = start;
            min = q->queuesize();
        }
        i++;
    } while (i<nr_choices);
    return choice;
}

uint32_t FatTreeSwitch::adaptive_route(vector<FibEntry*>* ecmp_set, int8_t (*cmp)(FibEntry*,FibEntry*)){
    //cout << "adaptive_route" << endl;
    uint32_t choice = 0;

    uint32_t best_choices[256];
    uint32_t best_choices_count = 0;
  
    FibEntry* min = (*ecmp_set)[choice];
    best_choices[best_choices_count++] = choice;

    for (uint32_t i = 1; i< ecmp_set->size(); i++){
        int8_t c = cmp(min,(*ecmp_set)[i]);

        if (c < 0){
            choice = i;
            min = (*ecmp_set)[choice];
            best_choices_count = 0;
            best_choices[best_choices_count++] = choice;
        }
        else if (c==0){
            assert(best_choices_count<255);
            best_choices[best_choices_count++] = i;
        }        
    }

    assert (best_choices_count>=1);
    uint32_t choiceindex = random()%best_choices_count;
    choice = best_choices[choiceindex];
    //cout << "ECMP set choices " << ecmp_set->size() << " Choice count " << best_choices_count << " chosen entry " << choiceindex << " chosen path " << choice << " ";

    if (cmp==compare_flow_count){
        //for (uint32_t i = 0; i<best_choices_count;i++)
          //  cout << "pathcnt " << best_choices[i] << "="<< _port_flow_counts[(BaseQueue*)( (*ecmp_set)[best_choices[i]]->getEgressPort()->at(0))]<< " ";
        
        _port_flow_counts[(BaseQueue*)((*ecmp_set)[choice]->getEgressPort()->at(0))]++;
    }

    return choice;
}

uint32_t FatTreeSwitch::replace_worst_choice(vector<FibEntry*>* ecmp_set, int8_t (*cmp)(FibEntry*,FibEntry*),uint32_t my_choice){
    uint32_t best_choice = 0;
    uint32_t worst_choice = 0;

    uint32_t best_choices[256];
    uint32_t best_choices_count = 0;

    FibEntry* min = (*ecmp_set)[best_choice];
    FibEntry* max = (*ecmp_set)[worst_choice];
    best_choices[best_choices_count++] = best_choice;

    for (uint32_t i = 1; i< ecmp_set->size(); i++){
        int8_t c = cmp(min,(*ecmp_set)[i]);

        if (c < 0){
            best_choice = i;
            min = (*ecmp_set)[best_choice];
            best_choices_count = 0;
            best_choices[best_choices_count++] = best_choice;
        }
        else if (c==0){
            assert(best_choices_count<256);
            best_choices[best_choices_count++] = i;
        }        

        if (cmp(max,(*ecmp_set)[i])>0){
            worst_choice = i;
            max = (*ecmp_set)[worst_choice];
        }
    }

    //might need to play with different alternatives here, compare to worst rather than just to worst index.
    int8_t r = cmp((*ecmp_set)[my_choice],(*ecmp_set)[worst_choice]);
    assert(r>=0);

    if (r==0){
        assert (best_choices_count>=1);
        return best_choices[random()%best_choices_count];
    }
    else return my_choice;
}


int8_t FatTreeSwitch::compare_pause(FibEntry* left, FibEntry* right){
    Route * r1= left->getEgressPort();
    assert(r1 && r1->size()>1);
    LosslessOutputQueue* q1 = dynamic_cast<LosslessOutputQueue*>(r1->at(0));
    Route * r2= right->getEgressPort();
    assert(r2 && r2->size()>1);
    LosslessOutputQueue* q2 = dynamic_cast<LosslessOutputQueue*>(r2->at(0));

    if (!q1->is_paused()&&q2->is_paused())
        return 1;
    else if (q1->is_paused()&&!q2->is_paused())
        return -1;
    else 
        return 0;
}

int8_t FatTreeSwitch::compare_flow_count(FibEntry* left, FibEntry* right){
    Route * r1= left->getEgressPort();
    assert(r1 && r1->size()>1);
    BaseQueue* q1 = (BaseQueue*)(r1->at(0));
    Route * r2= right->getEgressPort();
    assert(r2 && r2->size()>1);
    BaseQueue* q2 = (BaseQueue*)(r2->at(0));

    if (_port_flow_counts.find(q1)==_port_flow_counts.end())
        _port_flow_counts[q1] = 0;

    if (_port_flow_counts.find(q2)==_port_flow_counts.end())
        _port_flow_counts[q2] = 0;

    //cout << "CMP q1 " << q1 << "=" << _port_flow_counts[q1] << " q2 " << q2 << "=" << _port_flow_counts[q2] << endl; 

    if (_port_flow_counts[q1] < _port_flow_counts[q2])
        return 1;
    else if (_port_flow_counts[q1] > _port_flow_counts[q2] )
        return -1;
    else 
        return 0;
}

int8_t FatTreeSwitch::compare_queuesize(FibEntry* left, FibEntry* right){
    Route * r1= left->getEgressPort();
    assert(r1 && r1->size()>1);
    BaseQueue* q1 = dynamic_cast<BaseQueue*>(r1->at(0));
    Route * r2= right->getEgressPort();
    assert(r2 && r2->size()>1);
    BaseQueue* q2 = dynamic_cast<BaseQueue*>(r2->at(0));

    if (q1->quantized_queuesize() < q2->quantized_queuesize())
        return 1;
    else if (q1->quantized_queuesize() > q2->quantized_queuesize())
        return -1;
    else 
        return 0;
}

int8_t FatTreeSwitch::compare_bandwidth(FibEntry* left, FibEntry* right){
    Route * r1= left->getEgressPort();
    assert(r1 && r1->size()>1);
    BaseQueue* q1 = dynamic_cast<BaseQueue*>(r1->at(0));
    Route * r2= right->getEgressPort();
    assert(r2 && r2->size()>1);
    BaseQueue* q2 = dynamic_cast<BaseQueue*>(r2->at(0));

    if (q1->quantized_utilization() < q2->quantized_utilization())
        return 1;
    else if (q1->quantized_utilization() > q2->quantized_utilization())
        return -1;
    else 
        return 0;

    /*if (q1->average_utilization() < q2->average_utilization())
        return 1;
    else if (q1->average_utilization() > q2->average_utilization())
        return -1;
    else 
        return 0;        */
}

int8_t FatTreeSwitch::compare_pqb(FibEntry* left, FibEntry* right){
    //compare pause, queuesize, bandwidth.
    int8_t p = compare_pause(left, right);

    if (p!=0)
        return p;
    
    p = compare_queuesize(left,right);

    if (p!=0)
        return p;

    return compare_bandwidth(left,right);
}

int8_t FatTreeSwitch::compare_pq(FibEntry* left, FibEntry* right){
    //compare pause, queuesize, bandwidth.
    int8_t p = compare_pause(left, right);

    if (p!=0)
        return p;
    
    return compare_queuesize(left,right);
}

int8_t FatTreeSwitch::compare_qb(FibEntry* left, FibEntry* right){
    //compare pause, queuesize, bandwidth.
    int8_t p = compare_queuesize(left, right);

    if (p!=0)
        return p;
    
    return compare_bandwidth(left,right);
}

int8_t FatTreeSwitch::compare_pb(FibEntry* left, FibEntry* right){
    //compare pause, queuesize, bandwidth.
    int8_t p = compare_pause(left, right);

    if (p!=0)
        return p;
    
    return compare_bandwidth(left,right);
}

void FatTreeSwitch::permute_paths(vector<FibEntry *>* uproutes) {
    int len = uproutes->size();
    for (int i = 0; i < len; i++) {
        int ix = random() % (len - i);
        FibEntry* tmppath = (*uproutes)[ix];
        (*uproutes)[ix] = (*uproutes)[len-1-i];
        (*uproutes)[len-1-i] = tmppath;
    }
}

FatTreeSwitch::routing_strategy FatTreeSwitch::_strategy = FatTreeSwitch::NIX;
uint16_t FatTreeSwitch::_ar_fraction = 0;
uint16_t FatTreeSwitch::_ar_sticky = FatTreeSwitch::PER_PACKET;
simtime_picosec FatTreeSwitch::_sticky_delta = timeFromUs((uint32_t)10);
double FatTreeSwitch::_ecn_threshold_fraction = 0.2;
double FatTreeSwitch::_speculative_threshold_fraction = 0.2;
int8_t (*FatTreeSwitch::fn)(FibEntry*,FibEntry*)= &FatTreeSwitch::compare_queuesize;
uint16_t FatTreeSwitch::_trim_size = 64;
bool FatTreeSwitch::_disable_trim = false;
bool FatTreeSwitch::_enable_redr = false;

// REDR helper functions
uint32_t FatTreeSwitch::computePrimaryHash(Packet& pkt, vector<FibEntry*>* available_hops) {
    assert(available_hops && !available_hops->empty());
    // Base hash on flow id and path id, salted per switch
    uint32_t h = freeBSDHash(pkt.flow_id(), pkt.pathid(), _hash_salt);
    return h % available_hops->size();
}

uint32_t FatTreeSwitch::computeBackupHash(Packet& pkt, vector<FibEntry*>* available_hops) {
    assert(available_hops && !available_hops->empty());
    // Simple deterministic alternative: next port after primary
    uint32_t primary = computePrimaryHash(pkt, available_hops);
    if (available_hops->size() == 1) {
        return primary;
    }
    return (primary + 1) % available_hops->size();
}

bool FatTreeSwitch::portUp(uint32_t index, vector<FibEntry*>* available_hops) {
    if (!available_hops || index >= available_hops->size()) {
        return false;
    }
    FibEntry* e = (*available_hops)[index];
    if (!e) {
        return false;
    }
    Route* r = e->getEgressPort();
    if (!r || r->size() == 0) {
        return false;
    }
    // First element should be a queue; if it's null, treat link as down
    BaseQueue* q = dynamic_cast<BaseQueue*>(r->at(0));
    return q != nullptr;
}

bool FatTreeSwitch::portDown(uint32_t index, vector<FibEntry*>* available_hops) {
    return !portUp(index, available_hops);
}

bool FatTreeSwitch::loopDetected(Packet& pkt) {
    // For UEC data packets, consider another deflection as a potential loop
    if (pkt.type() == UECDATA) {
        UecDataPacket* uec_pkt = dynamic_cast<UecDataPacket*>(&pkt);
        if (uec_pkt) {
            return uec_pkt->is_deflected();
        }
    }
    return false;
}

Route* FatTreeSwitch::getNextHop(Packet& pkt, BaseQueue* ingress_port){
    vector<FibEntry*> * available_hops = _fib->getRoutes(pkt.dst());

    if (available_hops && !available_hops->empty()){
        // REDR Algorithm 3: Logic at switch upon packet arrival
        // Apply REDR to UEC data packets when REDR is enabled
        // Note: For rerouting when no routes exist, we handle all UEC packet types
        if (_enable_redr && pkt.type() == UECDATA) {
            uint32_t primary = computePrimaryHash(pkt, available_hops);
            
            if (portDown(primary, available_hops)) {
                // Primary port is down, try backup
                uint32_t backup = computeBackupHash(pkt, available_hops);
                
                if (primary == backup || loopDetected(pkt)) {
                    // Can't use backup (same as primary or loop detected), push back
                    // For now, fall through to use primary anyway (push back not implemented)
                    // In a real implementation, you'd queue the packet for later retry
                } else if (portUp(backup, available_hops)) {
                    // Use backup port - mark as deflected
                    FibEntry* primary_entry = (*available_hops)[primary];
                    FibEntry* backup_entry = (*available_hops)[backup];

                    // Debug: print original (primary) path and backup path chosen by REDR
                    if (primary_entry && backup_entry &&
                        primary_entry->getEgressPort() && backup_entry->getEgressPort()) {
                        cerr << "REDR link failure at switch type " << _type
                             << " id " << _id
                             << " for dst " << pkt.dst()
                             << " flow " << pkt.flow_id()
                             << " primary=" << primary << " backup=" << backup << endl;
                        cerr << "  Original path (primary): ";
                        print_route(*primary_entry->getEgressPort());
                        cerr << "  Rerouted path (backup):  ";
                        print_route(*backup_entry->getEgressPort());
                    }

                    packet_direction desired_dir = backup_entry->getDirection();
                    packet_direction current_dir = pkt.get_direction();
                    // Only set direction if it's valid (can't go from DOWN to UP)
                    if (desired_dir == DOWN || (current_dir == NONE) || (current_dir == UP && desired_dir == DOWN)) {
                        pkt.set_direction(desired_dir);
                    }
                    // Mark UEC data packet as deflected
                    UecDataPacket* uec_pkt = dynamic_cast<UecDataPacket*>(&pkt);
                    if (uec_pkt) {
                        uec_pkt->set_deflected(true);
                    }
                    return backup_entry->getEgressPort();
                } else {
                    // Backup also down, push back
                    // For now, fall through to use primary anyway (push back not implemented)
                }
            } else {
                // Primary port is up, use it
                FibEntry* e = (*available_hops)[primary];
                packet_direction desired_dir = e->getDirection();
                packet_direction current_dir = pkt.get_direction();
                // Only set direction if it's valid (can't go from DOWN to UP)
                if (desired_dir == DOWN || (current_dir == NONE) || (current_dir == UP && desired_dir == DOWN)) {
                    pkt.set_direction(desired_dir);
                }
                return e->getEgressPort();
            }
        }
        
        // Fall through to original routing logic for non-UEC packets or if REDR is disabled
        //implement a form of ECMP hashing; might need to revisit based on measured performance.
        uint32_t ecmp_choice = 0;  // Default to first available hop
        if (available_hops->size()>1)
            switch(_strategy){
            case NIX:
                abort();
            case ECMP:
                ecmp_choice = freeBSDHash(pkt.flow_id(),pkt.pathid(),_hash_salt) % available_hops->size();
                break;
            case ADAPTIVE_ROUTING:
                if (pkt.size() < 100) {
                    // don't bother adaptive routing the small packets - don't want to pollute the tables
                    ecmp_choice = freeBSDHash(pkt.flow_id(),pkt.pathid(),_hash_salt) % available_hops->size();
                    break;
                }
                if (_ar_sticky==FatTreeSwitch::PER_PACKET){
                    ecmp_choice = adaptive_route(available_hops,fn); 
                } 
                else if (_ar_sticky==FatTreeSwitch::PER_FLOWLET){     
                    if (_flowlet_maps.find(pkt.flow_id())!=_flowlet_maps.end()){
                        FlowletInfo* f = _flowlet_maps[pkt.flow_id()];
                        
                        // only reroute an existing flow if its inter packet time is larger than _sticky_delta and
                        // and
                        // 50% chance happens. 
                        // and (commented out) if the switch has not taken any other placement decision that we've not seen the effects of.
                        if (eventlist().now() - f->_last > _sticky_delta && /*eventlist().now() - _last_choice > _pipe->delay() + BaseQueue::_update_period  &&*/ random()%2==0){ 
                            //cout << "AR 1 " << timeAsUs(eventlist().now()) << endl;
                            uint32_t new_route = adaptive_route(available_hops,fn); 
                            if (fn(available_hops->at(f->_egress),available_hops->at(new_route)) < 0){
                                f->_egress = new_route;
                                _last_choice = eventlist().now();
                                //cout << "Switch " << _type << ":" << _id << " choosing new path "<<  f->_egress << " for " << pkt.flow_id() << " at " << timeAsUs(eventlist().now()) << " last is " << timeAsUs(f->_last) << endl;
                            }
                        }
                        ecmp_choice = f->_egress;

                        f->_last = eventlist().now();
                    }
                    else {
                        //cout << "AR 2 " << timeAsUs(eventlist().now()) << endl;
                        ecmp_choice = adaptive_route(available_hops,fn); 
                        _last_choice = eventlist().now();

                        _flowlet_maps[pkt.flow_id()] = new FlowletInfo(ecmp_choice,eventlist().now());
                    }
                }

                break;
            case ECMP_ADAPTIVE:
                ecmp_choice = freeBSDHash(pkt.flow_id(),pkt.pathid(),_hash_salt) % available_hops->size();
                if (random()%100 < 50)
                    ecmp_choice = replace_worst_choice(available_hops,fn, ecmp_choice);
                break;
            case RR:
                if (pkt.size()<128)
                    ecmp_choice = freeBSDHash(pkt.flow_id(),pkt.pathid(),_hash_salt) % available_hops->size();
                else {
                    if (_crt_route>=1*available_hops->size()){
                        _crt_route = 0;
                        permute_paths(available_hops);
                    }
                    ecmp_choice = _crt_route % available_hops->size();
                    _crt_route ++;
                }
                break;
            case RR_ECMP:
                if (_type == TOR){
                    if (_crt_route>=5 * available_hops->size()){
                        _crt_route = 0;
                        permute_paths(available_hops);
                    }
                    ecmp_choice = _crt_route % available_hops->size();
                    _crt_route ++;
                }
                else ecmp_choice = freeBSDHash(pkt.flow_id(),pkt.pathid(),_hash_salt) % available_hops->size();
                
                break;
            }
        
        FibEntry* e = (*available_hops)[ecmp_choice];
        packet_direction desired_dir = e->getDirection();
        packet_direction current_dir = pkt.get_direction();
        // Only set direction if it's valid (can't go from DOWN to UP)
        if (desired_dir == DOWN || (current_dir == NONE) || (current_dir == UP && desired_dir == DOWN)) {
            pkt.set_direction(desired_dir);
        }
        
        return e->getEgressPort();
    }

    //no route table entries for this destination. Add them to FIB or fail.
    // Check if routes exist but are empty (all routes skipped due to failed links)
    vector<FibEntry*>* existing_routes = _fib->getRoutes(pkt.dst());
    if (existing_routes && existing_routes->empty()) {
        // Routes were attempted to be built but all were skipped (failed links)
        // Return NULL to indicate no route available
        return NULL;
    }
    
    if (_type == TOR){
        if ( _ft->cfg().HOST_POD_SWITCH(pkt.dst()) == _id) { 
            //this host is directly connected!
            HostFibEntry* fe = _fib->getHostRoute(pkt.dst(),pkt.flow_id());
            assert(fe);
            pkt.set_direction(DOWN);
            return fe->getEgressPort();
        } else {
            //route packet up!
            if (_uproutes)
                _fib->setRoutes(pkt.dst(),_uproutes);
            else {
                uint32_t podid,agg_min,agg_max;

                if (_ft->cfg().get_tiers()==3) {
                    podid = _id / _ft->cfg().tor_switches_per_pod();
                    agg_min = _ft->cfg().MIN_POD_AGG_SWITCH(podid);
                    agg_max = _ft->cfg().MAX_POD_AGG_SWITCH(podid);
                }
                else {
                    agg_min = 0;
                    agg_max = _ft->cfg().getNAGG()-1;
                }

                // Ensure routes vector exists (will be created by first addRoute call)
                bool routes_added = false;
                for (uint32_t k=agg_min; k<=agg_max;k++){
                    for (uint32_t b = 0; b < _ft->cfg().bundlesize(AGG_TIER); b++) {
                        // Skip failed links (NULL queues/pipes)
                        if (_ft->queues_nlp_nup[_id][k][b] == NULL ||
                            _ft->pipes_nlp_nup[_id][k][b] == NULL) {
                            continue;
                        }
                        
                        Route * r = new Route();
                        r->push_back(_ft->queues_nlp_nup[_id][k][b]);
                        assert(((BaseQueue*)r->at(0))->getSwitch() == this);

                        r->push_back(_ft->pipes_nlp_nup[_id][k][b]);
                        r->push_back(_ft->queues_nlp_nup[_id][k][b]->getRemoteEndpoint());
                        _fib->addRoute(pkt.dst(),r,1,UP);
                        routes_added = true;
                    }

                    /*
                      FatTreeSwitch* next = (FatTreeSwitch*)_ft->queues_nlp_nup[_id][k]->getRemoteEndpoint();
                      assert (next->getType()==AGG && next->getID() == k);
                    */
                }
                // Ensure routes entry exists even if all routes were skipped (failed links)
                if (!routes_added) {
                    _fib->setRoutes(pkt.dst(), new vector<FibEntry*>());
                }
                _uproutes = _fib->getRoutes(pkt.dst());
                if (_uproutes && !_uproutes->empty()) {
                    permute_paths(_uproutes);
                }
            }
        }
    } else if (_type == AGG) {
        if (_ft->cfg().get_tiers()==2 || _ft->cfg().HOST_POD(pkt.dst()) == _ft->cfg().AGG_SWITCH_POD_ID(_id)) {
            //must go down!
            //target NLP id is 2 * pkt.dst()/K
            uint32_t target_tor = _ft->cfg().HOST_POD_SWITCH(pkt.dst());
            bool routes_added = false;
            for (uint32_t b = 0; b < _ft->cfg().bundlesize(AGG_TIER); b++) {
                // Skip failed links (NULL queues/pipes)
                if (_ft->queues_nup_nlp[_id][target_tor][b] == NULL ||
                    _ft->pipes_nup_nlp[_id][target_tor][b] == NULL) {
                    continue;
                }
                
                Route * r = new Route();
                r->push_back(_ft->queues_nup_nlp[_id][target_tor][b]);
                assert(((BaseQueue*)r->at(0))->getSwitch() == this);

                r->push_back(_ft->pipes_nup_nlp[_id][target_tor][b]);          
                r->push_back(_ft->queues_nup_nlp[_id][target_tor][b]->getRemoteEndpoint());

                _fib->addRoute(pkt.dst(),r,1, DOWN);
                routes_added = true;
            }
            // Ensure routes entry exists even if all routes were skipped (failed links)
            if (!routes_added) {
                _fib->setRoutes(pkt.dst(), new vector<FibEntry*>());
            }
        } else {
            //go up!
            if (_uproutes)
                _fib->setRoutes(pkt.dst(),_uproutes);
            else {
                uint32_t podpos = _id % _ft->cfg().agg_switches_per_pod();
                uint32_t uplink_bundles = _ft->cfg().radix_up(AGG_TIER) / _ft->cfg().bundlesize(CORE_TIER);
                bool routes_added = false;
                for (uint32_t l = 0; l <  uplink_bundles ; l++) {
                    uint32_t core = l * _ft->cfg().agg_switches_per_pod() + podpos;
                    for (uint32_t b = 0; b < _ft->cfg().bundlesize(CORE_TIER); b++) {
                        // Skip failed links (NULL queues/pipes)
                        if (_ft->queues_nup_nc[_id][core][b] == NULL ||
                            _ft->pipes_nup_nc[_id][core][b] == NULL) {
                            continue;
                        }
                        
                        Route *r = new Route();
                        r->push_back(_ft->queues_nup_nc[_id][core][b]);
                        assert(((BaseQueue*)r->at(0))->getSwitch() == this);

                        r->push_back(_ft->pipes_nup_nc[_id][core][b]);
                        r->push_back(_ft->queues_nup_nc[_id][core][b]->getRemoteEndpoint());

                        /*
                          FatTreeSwitch* next = (FatTreeSwitch*)_ft->queues_nup_nc[_id][k]->getRemoteEndpoint();
                          assert (next->getType()==CORE && next->getID() == k);
                        */
                    
                        _fib->addRoute(pkt.dst(),r,1,UP);
                        routes_added = true;

                        //cout << "AGG switch " << _id << " adding route to " << pkt.dst() << " via CORE " << k << " bundle_id " << b << endl;
                    }
                }
                // Ensure routes entry exists even if all routes were skipped (failed links)
                if (!routes_added) {
                    _fib->setRoutes(pkt.dst(), new vector<FibEntry*>());
                }
                vector<FibEntry*>* routes = _fib->getRoutes(pkt.dst());
                if (routes && !routes->empty()) {
                    permute_paths(routes);
                }
            }
        }
    } else if (_type == CORE) {
        uint32_t nup = _ft->cfg().MIN_POD_AGG_SWITCH(_ft->cfg().HOST_POD(pkt.dst())) + (_id % _ft->cfg().agg_switches_per_pod());
        bool routes_added = false;
        for (uint32_t b = 0; b < _ft->cfg().bundlesize(CORE_TIER); b++) {
            // Skip failed links (NULL queues/pipes)
            if (_ft->queues_nc_nup[_id][nup][b] == NULL ||
                _ft->pipes_nc_nup[_id][nup][b] == NULL) {
                continue;
            }
            
            Route *r = new Route();
            //cout << "CORE switch " << _id << " adding route to " << pkt.dst() << " via AGG " << nup << endl;

            r->push_back(_ft->queues_nc_nup[_id][nup][b]);
            assert(((BaseQueue*)r->at(0))->getSwitch() == this);

            r->push_back(_ft->pipes_nc_nup[_id][nup][b]);

            r->push_back(_ft->queues_nc_nup[_id][nup][b]->getRemoteEndpoint());
            _fib->addRoute(pkt.dst(),r,1,DOWN);
            routes_added = true;
        }
        // Ensure routes entry exists even if all routes were skipped (failed links)
        if (!routes_added) {
            _fib->setRoutes(pkt.dst(), new vector<FibEntry*>());
        }
    }
    else {
        cerr << "Route lookup on switch with no proper type: " << _type << endl;
        abort();
    }
    // Ensure routes exist (even if empty due to all links being failed)
    vector<FibEntry*>* routes = _fib->getRoutes(pkt.dst());
    if (!routes || routes->empty()) {
        // All routes were skipped due to failed links
        // Handle differently based on load balancing algorithm
        // Apply REDR rerouting for UEC packets when REDR is enabled
        // Handle all UEC packet types (data, ack, nack, pull, rts) since they all need routing
        if (_enable_redr && (pkt.type() == UECDATA || pkt.type() == UECACK || 
                             pkt.type() == UECNACK || pkt.type() == UECPULL || 
                             pkt.type() == UECRTS)) {
            // REDR Algorithm 3: Try to reroute back to previous switch
            // Get ingress port from parameter first, or from packet's ingress queue
            BaseQueue* ingress = ingress_port;
            if (!ingress) {
                // Try to get from packet's ingress queue (LosslessInputQueue sets it before calling receivePacket)
                // Since FatTreeSwitch is a friend of Packet, we can access _ingressqueue directly
                // This avoids the assertion in get_ingress_queue() while still accessing the queue
                if (pkt._ingressqueue) {
                    ingress = dynamic_cast<BaseQueue*>(pkt._ingressqueue);
                }
            }
            
            if (ingress && ingress->getRemoteEndpoint()) {
                // Get the previous switch/host from the ingress port
                // For LOSSLESS_INPUT topology:
                // - The ingress queue is a LosslessInputQueue on THIS switch
                // - The ingress queue's remote endpoint is the peer egress queue (on the previous switch)
                // - That egress queue belongs to the PREVIOUS switch
                // - However, the egress queue's remote endpoint was overwritten by LosslessInputQueue
                //   to point to the LosslessInputQueue on the previous switch
                // - So we need to get the switch from the egress queue directly
                PacketSink* prev_endpoint = ingress->getRemoteEndpoint();
                Switch* prev_switch = NULL;
                
                // Try to cast directly to Switch first (for non-LOSSLESS_INPUT topologies)
                prev_switch = dynamic_cast<Switch*>(prev_endpoint);
                
                // If that fails, the remote endpoint is a queue (egress queue on previous switch)
                if (!prev_switch) {
                    BaseQueue* prev_queue = dynamic_cast<BaseQueue*>(prev_endpoint);
                    if (prev_queue) {
                        // prev_queue is the egress queue on the previous switch
                        // Get the switch that owns this queue - that's the previous switch
                        prev_switch = prev_queue->getSwitch();
                        
                        // CRITICAL: Verify the queue belongs to a DIFFERENT switch
                        // If it belongs to this switch, we've misidentified it and should skip rerouting
                        if (prev_switch && prev_switch->getID() == _id) {
                            // The queue belongs to this switch - this shouldn't happen for a valid reroute
                            // This means we can't identify the previous switch correctly
                            // This can happen if the ingress queue's remote endpoint points to a queue
                            // on the same switch (which shouldn't happen in a properly configured topology)
                            // Skip rerouting to avoid a loop
                            prev_switch = NULL;
                            // Debug: This is the case that triggers "would loop back to same switch" warning
                        }
                    }
                }
                
                // Avoid loop: don't send back to the switch we came from (check by ID)
                if (prev_switch && prev_switch->getID() != _id) {
                    // Try to find an egress queue on this switch that connects back to previous switch
                    // In bidirectional fat tree with LOSSLESS_INPUT:
                    // - The ingress queue's remote endpoint is the peer egress queue (prev_endpoint)
                    // - Egress queues have their remote endpoint set to the switch (not the queue)
                    // - So we look for an egress queue on this switch whose remote endpoint is prev_switch
                    BaseQueue* reroute_queue = NULL;
                    
                    // First, try to find by iterating through ports
                    for (size_t i = 0; i < _ports.size(); i++) {
                        BaseQueue* q = _ports.at(i);
                        if (q && q->getRemoteEndpoint()) {
                            // Check if this egress queue's remote endpoint is the previous switch
                            Switch* remote_switch = dynamic_cast<Switch*>(q->getRemoteEndpoint());
                            if (remote_switch && remote_switch->getID() == prev_switch->getID()) {
                                reroute_queue = q;
                                break;
                            }
                            // Also check if remote endpoint is a queue that belongs to the previous switch
                            // (fallback for cases where remote endpoint might be a queue instead of switch)
                            if (!remote_switch) {
                                BaseQueue* remote_queue = dynamic_cast<BaseQueue*>(q->getRemoteEndpoint());
                                if (remote_queue && remote_queue->getSwitch() && 
                                    remote_queue->getSwitch()->getID() == prev_switch->getID()) {
                                    reroute_queue = q;
                                    break;
                                }
                            }
                        }
                    }
                    
                    // If not found in ports, try accessing topology arrays directly based on switch types
                    if (!reroute_queue && _ft) {
                        uint32_t prev_switch_id = prev_switch->getID();
                        switch_type prev_switch_type = static_cast<switch_type>(prev_switch->getType());
                        
                        if (_type == CORE && prev_switch_type == AGG) {
                            // CORE switch going back to AGG switch
                            // Look for queues_nc_nup[this_core][prev_agg][bundle]
                            for (uint32_t b = 0; b < _ft->cfg().bundlesize(CORE_TIER); b++) {
                                if (_ft->queues_nc_nup[_id][prev_switch_id][b] != NULL) {
                                    // Verify this queue's remote endpoint is the previous switch
                                    Switch* rem_sw = dynamic_cast<Switch*>(_ft->queues_nc_nup[_id][prev_switch_id][b]->getRemoteEndpoint());
                                    if (rem_sw && rem_sw->getID() == prev_switch_id) {
                                        reroute_queue = _ft->queues_nc_nup[_id][prev_switch_id][b];
                                        break;
                                    }
                                }
                            }
                        } else if (_type == AGG && prev_switch_type == CORE) {
                            // AGG switch going back to CORE switch
                            // Look for queues_nup_nc[this_agg][prev_core][bundle]
                            for (uint32_t b = 0; b < _ft->cfg().bundlesize(CORE_TIER); b++) {
                                if (_ft->queues_nup_nc[_id][prev_switch_id][b] != NULL) {
                                    Switch* rem_sw = dynamic_cast<Switch*>(_ft->queues_nup_nc[_id][prev_switch_id][b]->getRemoteEndpoint());
                                    if (rem_sw && rem_sw->getID() == prev_switch_id) {
                                        reroute_queue = _ft->queues_nup_nc[_id][prev_switch_id][b];
                                        break;
                                    }
                                }
                            }
                        } else if (_type == AGG && prev_switch_type == TOR) {
                            // AGG switch going back to TOR switch
                            // Look for queues_nup_nlp[this_agg][prev_tor][bundle]
                            for (uint32_t b = 0; b < _ft->cfg().bundlesize(AGG_TIER); b++) {
                                if (_ft->queues_nup_nlp[_id][prev_switch_id][b] != NULL) {
                                    Switch* rem_sw = dynamic_cast<Switch*>(_ft->queues_nup_nlp[_id][prev_switch_id][b]->getRemoteEndpoint());
                                    if (rem_sw && rem_sw->getID() == prev_switch_id) {
                                        reroute_queue = _ft->queues_nup_nlp[_id][prev_switch_id][b];
                                        break;
                                    }
                                }
                            }
                        } else if (_type == TOR && prev_switch_type == AGG) {
                            // TOR switch going back to AGG switch
                            // Look for queues_nlp_nup[this_tor][prev_agg][bundle]
                            for (uint32_t b = 0; b < _ft->cfg().bundlesize(AGG_TIER); b++) {
                                if (_ft->queues_nlp_nup[_id][prev_switch_id][b] != NULL) {
                                    Switch* rem_sw = dynamic_cast<Switch*>(_ft->queues_nlp_nup[_id][prev_switch_id][b]->getRemoteEndpoint());
                                    if (rem_sw && rem_sw->getID() == prev_switch_id) {
                                        reroute_queue = _ft->queues_nlp_nup[_id][prev_switch_id][b];
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    
                    if (reroute_queue) {
                        // Found a queue back to previous switch - create route
                        // Note: This uses the reverse direction of the bidirectional link
                        // Note: We do NOT clear the ingress queue here - LosslessOutputQueue needs it
                        // and will clear it. After LosslessOutputQueue clears it, when the packet arrives
                        // at the previous switch's LosslessInputQueue, that queue can set_ingress_queue().
                        Route* r = new Route();
                        r->push_back(reroute_queue);
                        
                        // Find the corresponding pipe for this queue
                        // Routes need: queue -> pipe -> remote_endpoint
                        Pipe* reroute_pipe = NULL;
                        uint32_t prev_switch_id = prev_switch->getID();
                        switch_type prev_switch_type = static_cast<switch_type>(prev_switch->getType());
                        
                        if (_type == CORE && prev_switch_type == AGG) {
                            // Find pipe for queues_nc_nup[this_core][prev_agg][bundle]
                            for (uint32_t b = 0; b < _ft->cfg().bundlesize(CORE_TIER); b++) {
                                if (_ft->queues_nc_nup[_id][prev_switch_id][b] == reroute_queue) {
                                    reroute_pipe = _ft->pipes_nc_nup[_id][prev_switch_id][b];
                                    break;
                                }
                            }
                        } else if (_type == AGG && prev_switch_type == CORE) {
                            // Find pipe for queues_nup_nc[this_agg][prev_core][bundle]
                            for (uint32_t b = 0; b < _ft->cfg().bundlesize(CORE_TIER); b++) {
                                if (_ft->queues_nup_nc[_id][prev_switch_id][b] == reroute_queue) {
                                    reroute_pipe = _ft->pipes_nup_nc[_id][prev_switch_id][b];
                                    break;
                                }
                            }
                        } else if (_type == AGG && prev_switch_type == TOR) {
                            // Find pipe for queues_nup_nlp[this_agg][prev_tor][bundle]
                            for (uint32_t b = 0; b < _ft->cfg().bundlesize(AGG_TIER); b++) {
                                if (_ft->queues_nup_nlp[_id][prev_switch_id][b] == reroute_queue) {
                                    reroute_pipe = _ft->pipes_nup_nlp[_id][prev_switch_id][b];
                                    break;
                                }
                            }
                        } else if (_type == TOR && prev_switch_type == AGG) {
                            // Find pipe for queues_nlp_nup[this_tor][prev_agg][bundle]
                            for (uint32_t b = 0; b < _ft->cfg().bundlesize(AGG_TIER); b++) {
                                if (_ft->queues_nlp_nup[_id][prev_switch_id][b] == reroute_queue) {
                                    reroute_pipe = _ft->pipes_nlp_nup[_id][prev_switch_id][b];
                                    break;
                                }
                            }
                        }
                        
                        // Add pipe if found (should always be found if queue exists)
                        if (reroute_pipe) {
                            r->push_back(reroute_pipe);
                        } else {
                            cerr << "Warning: Found reroute queue but no corresponding pipe for switch type " 
                                 << _type << " id " << _id << " to prev switch " << prev_switch_id << endl;
                        }
                        
                        // Add remote endpoint (the previous switch or its input queue)
                        PacketSink* remote_endpoint = reroute_queue->getRemoteEndpoint();
                        if (remote_endpoint) {
                            r->push_back(remote_endpoint);
                        }
                        // Mark packet as deflected/rerouted
                        if (pkt.type() == UECDATA) {
                            UecDataPacket* uec_pkt = dynamic_cast<UecDataPacket*>(&pkt);
                            if (uec_pkt) {
                                uec_pkt->set_deflected(true);
                            }
                        } else if (pkt.type() == UECACK) {
                            UecAckPacket* uec_ack = dynamic_cast<UecAckPacket*>(&pkt);
                            if (uec_ack) {
                                uec_ack->set_deflected(true);
                            }
                        }
                        // For rerouting, we're going back to the previous switch
                        // If we were going UP and need to go back, we should go DOWN
                        // If we were already going DOWN, we can't go UP (would be a loop)
                        // So only change direction if we were going UP
                        packet_direction current_dir = pkt.get_direction();
                        if (current_dir == UP) {
                            // Going back from UP direction - change to DOWN
                            pkt.set_direction(DOWN);
                        }
                        // If already DOWN or NONE, leave it as is (or set to DOWN if NONE)
                        else if (current_dir == NONE) {
                            pkt.set_direction(DOWN);
                        }
                        // If already DOWN, keep it DOWN (can't go UP - would be a loop)
                        return r;
                    }
                    // Debug: no matching egress queue found - provide more diagnostic info
                    cerr << "Warning: No valid routes to destination " << pkt.dst() 
                         << " from switch type " << _type << " id " << _id 
                         << " - found previous switch " << prev_switch->getID() 
                         << " but no egress queue connects to it (REDR)" << endl;
                    // Debug: check what ports we have and their remote endpoints
                    uint32_t ports_with_switches = 0;
                    uint32_t ports_with_queues = 0;
                    uint32_t ports_null = 0;
                    for (size_t i = 0; i < _ports.size(); i++) {
                        BaseQueue* q = _ports.at(i);
                        if (!q) {
                            ports_null++;
                            continue;
                        }
                        if (!q->getRemoteEndpoint()) {
                            ports_null++;
                            continue;
                        }
                        Switch* rem_sw = dynamic_cast<Switch*>(q->getRemoteEndpoint());
                        if (rem_sw) {
                            ports_with_switches++;
                            if (rem_sw->getID() == prev_switch->getID()) {
                                cerr << "  Debug: Found port " << i << " with remote switch id=" << rem_sw->getID() << " but comparison failed?" << endl;
                            }
                        } else {
                            BaseQueue* rem_q = dynamic_cast<BaseQueue*>(q->getRemoteEndpoint());
                            if (rem_q) {
                                ports_with_queues++;
                                if (rem_q->getSwitch() && rem_q->getSwitch()->getID() == prev_switch->getID()) {
                                    cerr << "  Debug: Found port " << i << " with remote queue on switch id=" << rem_q->getSwitch()->getID() << " but comparison failed?" << endl;
                                }
                            }
                        }
                    }
                    cerr << "  Debug: Total ports=" << _ports.size() << " with_switches=" << ports_with_switches 
                         << " with_queues=" << ports_with_queues << " null=" << ports_null << endl;
                } else {
                    // Debug: loop detected or no previous switch
                    if (!prev_switch) {
                        cerr << "Warning: No valid routes to destination " << pkt.dst() 
                             << " from switch type " << _type << " id " << _id 
                             << " - previous endpoint is not a switch (REDR)" << endl;
                    } else {
                        cerr << "Warning: No valid routes to destination " << pkt.dst() 
                             << " from switch type " << _type << " id " << _id 
                             << " - would loop back to same switch " << prev_switch->getID() << " (REDR)" << endl;
                    }
                }
            } else {
                // Debug: no ingress queue or remote endpoint
                if (!ingress) {
                    // Ingress queue is NULL - this happens with composite_ecn queue type where packets
                    // arrive through regular queues instead of LosslessInputQueue
                    // Try to use packet's route to determine previous hop as fallback
                    PacketSink* prev_hop = NULL;
                    if (pkt.route() && pkt.nexthop() > 0) {
                        prev_hop = pkt.previousHop();
                        if (prev_hop) {
                            // Found previous hop from route - try to find corresponding egress queue
                            // Note: prev_hop is a PacketSink (could be queue, pipe, or switch)
                            // We need to find the queue on this switch that connects to it
                            BaseQueue* prev_queue = dynamic_cast<BaseQueue*>(prev_hop);
                            if (prev_queue && prev_queue->getRemoteEndpoint()) {
                                PacketSink* prev_endpoint = prev_queue->getRemoteEndpoint();
                                Switch* prev_switch = dynamic_cast<Switch*>(prev_endpoint);
                                if (prev_switch && prev_switch->getID() != _id) {
                                    // Try to find an egress queue that connects back
                                    // This is a fallback path - try to find queue by matching remote endpoint
                                    // Note: This path is less reliable than the main rerouting logic above
                                    for (size_t i = 0; i < _ports.size(); i++) {
                                        BaseQueue* q = _ports.at(i);
                                        if (q && q->getRemoteEndpoint() == prev_endpoint) {
                                            Route* r = new Route();
                                            r->push_back(q);
                                            
                                            // Try to find corresponding pipe (routes need: queue -> pipe -> remote_endpoint)
                                            // This is a simplified fallback - may not always find the pipe
                                            // In a complete implementation, we'd look up the pipe from topology arrays
                                            PacketSink* remote_endpoint = q->getRemoteEndpoint();
                                            if (remote_endpoint) {
                                                r->push_back(remote_endpoint);
                                            }
                                            
                                            if (pkt.type() == UECDATA) {
                                                UecDataPacket* uec_pkt = dynamic_cast<UecDataPacket*>(&pkt);
                                                if (uec_pkt) uec_pkt->set_deflected(true);
                                            } else if (pkt.type() == UECACK) {
                                                UecAckPacket* uec_ack = dynamic_cast<UecAckPacket*>(&pkt);
                                                if (uec_ack) uec_ack->set_deflected(true);
                                            }
                                            // For rerouting, we're going back to the previous switch
                                            // If we were going UP and need to go back, we should go DOWN
                                            // If we were already going DOWN, we can't go UP (would be a loop)
                                            // So only change direction if we were going UP
                                            packet_direction current_dir = pkt.get_direction();
                                            if (current_dir == UP) {
                                                // Going back from UP direction - change to DOWN
                                                pkt.set_direction(DOWN);
                                            }
                                            // If already DOWN or NONE, leave it as is (or set to DOWN if NONE)
                                            else if (current_dir == NONE) {
                                                pkt.set_direction(DOWN);
                                            }
                                            // If already DOWN, keep it DOWN (can't go UP - would be a loop)
                                            return r;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Could not determine previous switch - rerouting not possible
                    cerr << "Warning: No valid routes to destination " << pkt.dst() 
                         << " from switch type " << _type << " id " << _id 
                         << " - cannot reroute back (ingress queue not available with composite_ecn, REDR)" << endl;
                    // Note: With composite_ecn queue type, packets arrive through regular queues that don't
                    // set the ingress queue, so we cannot determine the previous switch for rerouting.
                    // Rerouting requires LOSSLESS_INPUT or LOSSLESS_INPUT_ECN queue types.
                } else {
                    cerr << "Warning: No valid routes to destination " << pkt.dst() 
                         << " from switch type " << _type << " id " << _id 
                         << " - ingress queue has no remote endpoint (REDR)" << endl;
                }
            }
            // If we can't reroute back, drop the packet (no valid route)
            return NULL;
        } else {
            // Not REDR or not UEC data packet - treat as lost packet
            // Debug info to understand why REDR wasn't applied
            cerr << "Warning: No valid routes to destination " << pkt.dst() 
                 << " from switch type " << _type << " id " << _id;
            if (!_enable_redr) {
                cerr << " (REDR disabled, packet lost under REPS)";
            } else if (pkt.type() != UECDATA) {
                cerr << " (packet type=" << pkt.type() << " != UECDATA, packet lost)";
            } else {
                cerr << " (packet lost under REPS)";
            }
            cerr << endl;
            return NULL;
        }
    }

    //FIB has been filled in; return choice. 
    return getNextHop(pkt, ingress_port);
};
