src := attrs.c bgp.c packets.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

tests_objs := $(tests_objs) $(src-o-files)
tests_src := packets_test.c
tests_targets := $(tests_targets) $(tests-target-files)
