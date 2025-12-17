// -*- c-basic-offset: 4; indent-tabs-mode: nil -*-
#include "fat_tree_switch.h"
#include "routetable.h"
#include "fat_tree_topology.h"
#include "callback_pipe.h"
#include "queue_lossless.h"
#include "queue_lossless_output.h"
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

        Route * nh = getNextHop(pkt,NULL);
        if (!nh) {
            // No route available - drop packet
            _packets.erase(&pkt);
            pkt.free();
            return;
        }
        //set next hop which is peer switch.
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
uint64_t FatTreeSwitch::_redr_failed_link_count = 0;
uint16_t FatTreeSwitch::_ar_sticky = FatTreeSwitch::PER_PACKET;
simtime_picosec FatTreeSwitch::_sticky_delta = timeFromUs((uint32_t)10);
double FatTreeSwitch::_ecn_threshold_fraction = 0.2;
double FatTreeSwitch::_speculative_threshold_fraction = 0.2;
int8_t (*FatTreeSwitch::fn)(FibEntry*,FibEntry*)= &FatTreeSwitch::compare_queuesize;
uint16_t FatTreeSwitch::_trim_size = 64;
bool FatTreeSwitch::_disable_trim = false;

Route* FatTreeSwitch::getNextHop(Packet& pkt, BaseQueue* ingress_port){
    vector<FibEntry*> * available_hops = _fib->getRoutes(pkt.dst());

    if (available_hops){
        //implement a form of ECMP hashing; might need to revisit based on measured performance.
        uint32_t ecmp_choice = 0;
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
            case REDR: {
                // Algorithm: REDR Logic at the switch upon packet arrival
                // For REDR, hash into total possible links, then check if that link exists
                uint16_t old_ev = pkt.pathid();
                BaseQueue* primary_queue = NULL;
                BaseQueue* backup_queue = NULL;
                uint32_t primary_route_idx = 0;
                uint32_t backup_route_idx = 0;
                bool primary_failed = false;
                bool backup_found = false;
                
                if (_type == AGG) {
                    if (_ft->cfg().get_tiers()==2 || _ft->cfg().HOST_POD(pkt.dst()) == _ft->cfg().AGG_SWITCH_POD_ID(_id)) {
                        // Routing DOWN to TOR
                        uint32_t target_tor = _ft->cfg().HOST_POD_SWITCH(pkt.dst());
                        uint32_t total_bundles = _ft->cfg().bundlesize(AGG_TIER);
                        uint32_t primary_bundle = freeBSDHash(pkt.flow_id(), pkt.pathid(), _hash_salt) % total_bundles;
                        uint32_t backup_bundle = freeBSDHash(pkt.flow_id(), pkt.pathid(), _hash_salt + 1) % total_bundles;
                        
                        // Check primary link
                        primary_queue = _ft->queues_nup_nlp[_id][target_tor][primary_bundle];
                        if (!primary_queue || !_ft->pipes_nup_nlp[_id][target_tor][primary_bundle]) {
                            primary_failed = true;
                            _redr_failed_link_count++;
                            // Find backup in available_hops
                            backup_queue = _ft->queues_nup_nlp[_id][target_tor][backup_bundle];
                            if (backup_queue && _ft->pipes_nup_nlp[_id][target_tor][backup_bundle]) {
                                // Find backup route in available_hops
                                for (uint32_t i = 0; i < available_hops->size(); i++) {
                                    Route* r = (*available_hops)[i]->getEgressPort();
                                    if (r && r->size() > 0) {
                                        BaseQueue* q = dynamic_cast<BaseQueue*>(r->at(0));
                                        if (q == backup_queue) {
                                            backup_route_idx = i;
                                            backup_found = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        } else {
                            // Find primary in available_hops
                            for (uint32_t i = 0; i < available_hops->size(); i++) {
                                Route* r = (*available_hops)[i]->getEgressPort();
                                if (r && r->size() > 0) {
                                    BaseQueue* q = dynamic_cast<BaseQueue*>(r->at(0));
                                    if (q == primary_queue) {
                                        primary_route_idx = i;
                                        break;
                                    }
                                }
                            }
                        }
                    } else {
                        // Routing UP to CORE
                        uint32_t podpos = _id % _ft->cfg().agg_switches_per_pod();
                        uint32_t total_links = _ft->cfg().radix_up(AGG_TIER);
                        uint32_t primary_link = freeBSDHash(pkt.flow_id(), pkt.pathid(), _hash_salt) % total_links;
                        uint32_t backup_link = freeBSDHash(pkt.flow_id(), pkt.pathid(), _hash_salt + 1) % total_links;
                        
                        // Convert link index to core and bundle
                        uint32_t primary_l = primary_link / _ft->cfg().bundlesize(CORE_TIER);
                        uint32_t primary_b = primary_link % _ft->cfg().bundlesize(CORE_TIER);
                        uint32_t primary_core = podpos + _ft->cfg().agg_switches_per_pod() * primary_l;
                        
                        uint32_t backup_l = backup_link / _ft->cfg().bundlesize(CORE_TIER);
                        uint32_t backup_b = backup_link % _ft->cfg().bundlesize(CORE_TIER);
                        uint32_t backup_core = podpos + _ft->cfg().agg_switches_per_pod() * backup_l;
                        
                        // Check primary link
                        if (primary_core >= _ft->cfg().no_of_cores() || 
                            !_ft->queues_nup_nc[_id][primary_core][primary_b] || 
                            !_ft->pipes_nup_nc[_id][primary_core][primary_b]) {
                            primary_failed = true;
                            _redr_failed_link_count++;
                            cout << "[REDR Switch] Detected failed link (AGG UP): switch=" << _type << ":" << _id
                                 << " primary_core=" << primary_core << " bundle=" << primary_b
                                 << " primary_link=" << primary_link << " flow=" << pkt.flow_id()
                                 << " total_failures=" << _redr_failed_link_count << endl;
                            // Check backup link
                            if (backup_core < _ft->cfg().no_of_cores() && 
                                _ft->queues_nup_nc[_id][backup_core][backup_b] && 
                                _ft->pipes_nup_nc[_id][backup_core][backup_b]) {
                                backup_queue = _ft->queues_nup_nc[_id][backup_core][backup_b];
                                // Find backup route in available_hops
                                for (uint32_t i = 0; i < available_hops->size(); i++) {
                                    Route* r = (*available_hops)[i]->getEgressPort();
                                    if (r && r->size() > 0) {
                                        BaseQueue* q = dynamic_cast<BaseQueue*>(r->at(0));
                                        if (q == backup_queue) {
                                            backup_route_idx = i;
                                            backup_found = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        } else {
                            primary_queue = _ft->queues_nup_nc[_id][primary_core][primary_b];
                            // Find primary in available_hops
                            for (uint32_t i = 0; i < available_hops->size(); i++) {
                                Route* r = (*available_hops)[i]->getEgressPort();
                                if (r && r->size() > 0) {
                                    BaseQueue* q = dynamic_cast<BaseQueue*>(r->at(0));
                                    if (q == primary_queue) {
                                        primary_route_idx = i;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // TOR or CORE: fall back to ECMP behavior (hash into available routes)
                    primary_route_idx = freeBSDHash(pkt.flow_id(), pkt.pathid(), _hash_salt) % available_hops->size();
                    backup_route_idx = freeBSDHash(pkt.flow_id(), pkt.pathid(), _hash_salt + 1) % available_hops->size();
                    
                    Route* primary_route = (*available_hops)[primary_route_idx]->getEgressPort();
                    primary_queue = (primary_route && primary_route->size() > 0) ? 
                        dynamic_cast<BaseQueue*>(primary_route->at(0)) : NULL;
                    primary_failed = (primary_queue == NULL);
                    if (primary_failed) {
                        _redr_failed_link_count++;
                        cout << "[REDR Switch] Detected failed link (TOR/CORE): switch=" << _type << ":" << _id
                             << " primary_route_idx=" << primary_route_idx << " flow=" << pkt.flow_id()
                             << " total_failures=" << _redr_failed_link_count << endl;
                    }
                    
                    if (primary_failed && backup_route_idx != primary_route_idx) {
                        Route* backup_route = (*available_hops)[backup_route_idx]->getEgressPort();
                        backup_queue = (backup_route && backup_route->size() > 0) ? 
                            dynamic_cast<BaseQueue*>(backup_route->at(0)) : NULL;
                        backup_found = (backup_queue != NULL);
                    }
                }
                
                if (primary_failed && backup_found) {
                    // Use backup and mark as deflected
                    ecmp_choice = backup_route_idx;
                    UecDataPacket* uec_pkt = dynamic_cast<UecDataPacket*>(&pkt);
                    if (uec_pkt) {
                        uec_pkt->set_deflected(true);
                        cout << "[REDR Switch] DEFLECTING: switch=" << _type << ":" << _id
                             << " flow=" << pkt.flow_id() << " dst=" << pkt.dst()
                             << " old_ev=" << old_ev << " -> backup_route_idx=" << backup_route_idx << endl;
                    }
                } else {
                    // Use primary (or first available if both failed)
                    ecmp_choice = primary_failed ? 0 : primary_route_idx;
                }
                break;
            }
            }
        
        FibEntry* e = (*available_hops)[ecmp_choice];
        pkt.set_direction(e->getDirection());
        
        return e->getEgressPort();
    }

    //no route table entries for this destination. Add them to FIB or fail. 
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

                for (uint32_t k=agg_min; k<=agg_max;k++){
                    for (uint32_t b = 0; b < _ft->cfg().bundlesize(AGG_TIER); b++) {
                        // Skip failed links (NULL queues)
                        if (!_ft->queues_nlp_nup[_id][k][b] || !_ft->pipes_nlp_nup[_id][k][b]) {
                            continue;
                        }
                        Route * r = new Route();
                        r->push_back(_ft->queues_nlp_nup[_id][k][b]);
                        assert(((BaseQueue*)r->at(0))->getSwitch() == this);

                        r->push_back(_ft->pipes_nlp_nup[_id][k][b]);
                        r->push_back(_ft->queues_nlp_nup[_id][k][b]->getRemoteEndpoint());
                        _fib->addRoute(pkt.dst(),r,1,UP);
                    }

                    /*
                      FatTreeSwitch* next = (FatTreeSwitch*)_ft->queues_nlp_nup[_id][k]->getRemoteEndpoint();
                      assert (next->getType()==AGG && next->getID() == k);
                    */
                }
                _uproutes = _fib->getRoutes(pkt.dst());
                if (_uproutes) {
                    permute_paths(_uproutes);
                }
            }
        }
    } else if (_type == AGG) {
        if (_ft->cfg().get_tiers()==2 || _ft->cfg().HOST_POD(pkt.dst()) == _ft->cfg().AGG_SWITCH_POD_ID(_id)) {
            //must go down!
            //target NLP id is 2 * pkt.dst()/K
            uint32_t target_tor = _ft->cfg().HOST_POD_SWITCH(pkt.dst());
            for (uint32_t b = 0; b < _ft->cfg().bundlesize(AGG_TIER); b++) {
                // Skip failed links (NULL queues or pipes)
                if (!_ft->queues_nup_nlp[_id][target_tor][b] || !_ft->pipes_nup_nlp[_id][target_tor][b]) {
                    continue;
                }
                Route * r = new Route();
                r->push_back(_ft->queues_nup_nlp[_id][target_tor][b]);
                assert(((BaseQueue*)r->at(0))->getSwitch() == this);

                r->push_back(_ft->pipes_nup_nlp[_id][target_tor][b]);          
                r->push_back(_ft->queues_nup_nlp[_id][target_tor][b]->getRemoteEndpoint());

                _fib->addRoute(pkt.dst(),r,1, DOWN);
            }
        } else {
            //go up!
            if (_uproutes)
                _fib->setRoutes(pkt.dst(),_uproutes);
            else {
                uint32_t podpos = _id % _ft->cfg().agg_switches_per_pod();
                uint32_t uplink_bundles = _ft->cfg().radix_up(AGG_TIER) / _ft->cfg().bundlesize(CORE_TIER);
                    for (uint32_t l = 0; l <  uplink_bundles ; l++) {
                    uint32_t core = l * _ft->cfg().agg_switches_per_pod() + podpos;
                    for (uint32_t b = 0; b < _ft->cfg().bundlesize(CORE_TIER); b++) {
                        // Skip failed links (NULL queues)
                        if (!_ft->queues_nup_nc[_id][core][b] || !_ft->pipes_nup_nc[_id][core][b]) {
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

                        //cout << "AGG switch " << _id << " adding route to " << pkt.dst() << " via CORE " << k << " bundle_id " << b << endl;
                    }
                }
                //_uproutes = _fib->getRoutes(pkt.dst());
                vector<FibEntry*>* routes = _fib->getRoutes(pkt.dst());
                if (routes) {
                    permute_paths(routes);
                }
            }
        }
    } else if (_type == CORE) {
        uint32_t nup = _ft->cfg().MIN_POD_AGG_SWITCH(_ft->cfg().HOST_POD(pkt.dst())) + (_id % _ft->cfg().agg_switches_per_pod());
        for (uint32_t b = 0; b < _ft->cfg().bundlesize(CORE_TIER); b++) {
            // Skip failed links (NULL queues)
            if (!_ft->queues_nc_nup[_id][nup][b] || !_ft->pipes_nc_nup[_id][nup][b]) {
                continue;
            }
            Route *r = new Route();
            //cout << "CORE switch " << _id << " adding route to " << pkt.dst() << " via AGG " << nup << endl;

            r->push_back(_ft->queues_nc_nup[_id][nup][b]);
            assert(((BaseQueue*)r->at(0))->getSwitch() == this);

            r->push_back(_ft->pipes_nc_nup[_id][nup][b]);

            r->push_back(_ft->queues_nc_nup[_id][nup][b]->getRemoteEndpoint());
            _fib->addRoute(pkt.dst(),r,1,DOWN);
        }
    }
    else {
        cerr << "Route lookup on switch with no proper type: " << _type << endl;
        abort();
    }
    
    // Check if routes were actually created (some links might be failed)
    vector<FibEntry*>* routes = _fib->getRoutes(pkt.dst());
    if (!routes || routes->empty()) {
        // No routes available (all links failed) - drop packet
        cerr << "Warning: No routes available for destination " << pkt.dst() 
             << " on switch " << _type << ":" << _id;
        if (_type == AGG) {
            if (_ft->cfg().get_tiers()==2 || _ft->cfg().HOST_POD(pkt.dst()) == _ft->cfg().AGG_SWITCH_POD_ID(_id)) {
                cerr << " (routing DOWN, target_tor=" << _ft->cfg().HOST_POD_SWITCH(pkt.dst()) 
                     << ", bundlesize=" << _ft->cfg().bundlesize(AGG_TIER) << ")";
            } else {
                uint32_t podpos = _id % _ft->cfg().agg_switches_per_pod();
                uint32_t uplink_bundles = _ft->cfg().radix_up(AGG_TIER) / _ft->cfg().bundlesize(CORE_TIER);
                cerr << " (routing UP, podpos=" << podpos << ", uplink_bundles=" << uplink_bundles << ")";
            }
        }
        cerr << " (all links failed)" << endl;
        // Return NULL route to indicate packet should be dropped
        return NULL;
    }

    //FIB has been filled in; return choice. 
    return getNextHop(pkt, ingress_port);
};
