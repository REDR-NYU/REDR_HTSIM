# Parameters Setting
EXECUTABLE="../../build/datacenter/htsim_uec"
TOPOLOGY="../topologies/topo_assignment2/fat_tree_128_1os.topo"
CONNECTION_MATRIX="../connection_matrices/cm_assignment2/four_with_failure.cm"



algo="redr"

# Run experiment
$EXECUTABLE \
    -nodes 128 \
    -topo "$TOPOLOGY" \
    -tm "$CONNECTION_MATRIX" \
    -sender_cc_algo dctcp \
    -load_balancing_algo "$algo" \
    -queue_type composite_ecn \
    -q 100 \
    -ecn 20 80 \
    -paths 200 \
    -cwnd 10 \
    -mtu 1500 \
    -end 1000 \
    -failed 0 \
    -log flow_events \
    -seed 0

