/**************************************************************************
gPXE -  Network Bootstrap Program

Literature dealing with the network protocols:
	ARP - RFC826
	RARP - RFC903
	UDP - RFC768
	BOOTP - RFC951, RFC2132 (vendor extensions)
	DHCP - RFC2131, RFC2132 (options)
	TFTP - RFC1350, RFC2347 (options), RFC2348 (blocksize), RFC2349 (tsize)
	RPC - RFC1831, RFC1832 (XDR), RFC1833 (rpcbind/portmapper)
	NFS - RFC1094, RFC1813 (v3, useful for clarifications, not implemented)
	IGMP - RFC1112

**************************************************************************/

#include <stdio.h>
#include <gpxe/init.h>
#include <gpxe/features.h>
#include <gpxe/shell.h>
#include <gpxe/shell_banner.h>
#include <usr/autoboot.h>

#define NORMAL	"\033[0m"
#define BOLD	"\033[1m"
#define CYAN	"\033[36m"

static struct feature features[0] __table_start ( struct feature, features );
static struct feature features_end[0] __table_end ( struct feature, features );

/**
 * Main entry point
 *
 * @ret rc		Return status code
 */
__cdecl int main ( void ) {
	struct feature *feature;

	initialise();
	startup();

	/* Print welcome banner */
	printf ( NORMAL "\n\n\n" BOLD "gPXE " VERSION
		 NORMAL " -- Open Source Boot Firmware -- "
		 CYAN "http://etherboot.org" NORMAL "\n"
		 "Features:" );
	for ( feature = features ; feature < features_end ; feature++ )
		printf ( " %s", feature->name );
	printf ( "\n" );

	/* Prompt for shell */
	if ( shell_banner() ) {
		/* User wants shell; just give them a shell */
		shell();
	} else {
		/* User doesn't want shell; try booting.  If booting
		 * fails, offer a second chance to enter the shell for
		 * diagnostics.
		 */
		autoboot();
		if ( shell_banner() )
			shell();
	}

	shutdown();

	return 0;
}