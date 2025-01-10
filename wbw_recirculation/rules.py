# Mirror rules
bfrt.mirror.cfg.add_with_normal(sid=1, direction="INGRESS", ucast_egress_port = 64, ucast_egress_port_valid = True, session_enable = True)
bfrt.mirror.cfg.add_with_normal(sid=2, direction="INGRESS", ucast_egress_port = 65, ucast_egress_port_valid = True, session_enable = True)

# Recirculate, mirror and forwarding set up rules
bfrt.demo.pipe.IngressControl.t_setup_mirror_rclt.add_with_a_setup_mirror_rclt("192.168.1.1", 2, 68)
bfrt.demo.pipe.IngressControl.t_setup_mirror_rclt.add_with_a_setup_mirror_rclt("192.168.1.2", 1, 68)

bfrt.demo.pipe.IngressControl.t_save_state_and_recirculate.add_with_a_save_state_and_recirculate(0, 0, 1000, 68)

bfrt.demo.pipe.IngressControl.t_arp.add_with_a_arp("192.168.1.1", "7a:5b:35:84:ee:58")
bfrt.demo.pipe.IngressControl.t_arp.add_with_a_arp("192.168.1.2", "02:b5:24:d8:2a:58")
bfrt.demo.pipe.IngressControl.t_forward.add_with_a_forward("192.168.1.2", 1)
bfrt.demo.pipe.IngressControl.t_fixed_parse.add_with_a_fixed_parse(0x6164646974656d2f,0x63617274,0x2c)
# bfrt.demo.pipe.IngressControl.t_filter_0_0.add_with_a_filter_0_0(0x55736572,0x0,0x0,0x0,0x0,0x0,0x0,0x4964,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x3132,0x33 )
# bfrt.demo.pipe.IngressControl.t_filter_0_1.add_with_a_filter_0_1(0x55736572,0x0,0x0,0x0,0x0,0x0,0x0,0x4964,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x3132,0x33 )
# bfrt.demo.pipe.IngressControl.t_filter_1_0.add_with_a_filter_1_0(0x50726f64,0x75637449,0x0,0x0,0x0,0x0,0x0,0x0,0x44,0x31323334,0x35363738,0x0,0x0,0x0,0x0,0x0,0x3930,0x0 )
# bfrt.demo.pipe.IngressControl.t_filter_1_1.add_with_a_filter_1_1(0x50726f64,0x75637449,0x0,0x0,0x0,0x0,0x0,0x0,0x44,0x31323334,0x35363738,0x0,0x0,0x0,0x0,0x0,0x3930,0x0 )

bfrt.demo.pipe.IngressControl.t_filter_0_0.add_with_a_filter_0_0(0x55736572,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x643a,0x49,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x3132332c,0x0,0x0 )
bfrt.demo.pipe.IngressControl.t_filter_0_1.add_with_a_filter_0_1(0x55736572,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x643a,0x49,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x3132332c,0x0,0x0 )
bfrt.demo.pipe.IngressControl.t_filter_1_0.add_with_a_filter_1_0(0x50726f64,0x75637449,0x0,0x0,0x0,0x0,0x0,0x0,0x443a,0x0,0x31323334,0x35363738,0x0,0x0,0x0,0x0,0x0,0x0,0x302c ,0x39)
bfrt.demo.pipe.IngressControl.t_filter_1_1.add_with_a_filter_1_1(0x50726f64,0x75637449,0x0,0x0,0x0,0x0,0x0,0x0,0x443a,0x0,0x31323334,0x35363738,0x0,0x0,0x0,0x0,0x0,0x0,0x302c ,0x39)

# bfrt.demo.pipe.IngressControl.c_tot_cnt.get(0, from_hw=1)

# bfrt.demo.pipe.IngressControl.rclt_tot_cnt.get(0, from_hw=1)
# bfrt.demo.pipe.IngressControl.check0.get(0, from_hw=1)
# bfrt.demo.pipe.IngressControl.check1.get(0, from_hw=1)
# bfrt.demo.pipe.IngressControl.check2.get(0, from_hw=1)
# bfrt.demo.pipe.IngressControl.check01.get(0, from_hw=1)
# bfrt.demo.pipe.IngressControl.check02.get(0, from_hw=1)
# bfrt.demo.pipe.IngressControl.check03.get(0, from_hw=1)
# bfrt.demo.pipe.IngressControl.check2.get(0, from_hw=1)

# bfrt.demo.pipe.IngressControl.c_tot_cnt.clear()

# bfrt.demo.pipe.IngressControl.rclt_tot_cnt.clear()
# bfrt.demo.pipe.IngressControl.check0.clear()
# bfrt.demo.pipe.IngressControl.check1.clear()
# bfrt.demo.pipe.IngressControl.check01.clear()
# bfrt.demo.pipe.IngressControl.check02.clear()
# bfrt.demo.pipe.IngressControl.check03.clear()
# bfrt.demo.pipe.IngressControl.check2.clear()