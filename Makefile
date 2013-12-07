# See LICENSE for licensing information.

PROJECT = ct_helper

# Options.

ERLC_OPTS = +debug_info
PLT_APPS = crypto public_key

# Standard targets.

include erlang.mk
