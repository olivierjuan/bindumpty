/* toy01_impl.c — translation unit that exposes ONLY the functions under
 * reconstruction (the impl header), for the M2 shared-object build.
 * toy01.c adds main(); this file does not — a .so cannot have two mains and
 * the harness provides the driver. */
#include "toy01_impl.h"
