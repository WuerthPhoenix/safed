// NTService.cpp

#include "NTServApp.h"
#include "Safed.h"


int main(int argc, char* argv[])
{
    // Create the service object
    CSafedService CustomServiceObject;
#ifdef DEBUG_TO_FILE
	setSAFEDDEBUG(9);
#endif

    // Parse for standard arguments (install, uninstall, version etc.)
    if (!CustomServiceObject.ParseStandardArgs(argc, argv)) 
	{
		CustomServiceObject.DebugMsg("Args grabbed");
		if(argc>1) {
			CustomServiceObject.DebugMsg("there are args");

			
			// we're debugging, so fake a few calls & run as a console app
			if (CustomServiceObject.OnInit())
			{
				CustomServiceObject.m_bIsRunning = TRUE;
				CustomServiceObject.Run();
			}
			
		} else {
			CustomServiceObject.DebugMsg("no args");
//remove this for live debugging of the service using VIsual Studio Debug/Attach to Process.
#ifndef _DEBUG
			// Didn't find any standard args so start the service
			CustomServiceObject.StartService();
#else
			// we're debugging, so fake a few calls & run as a console app
			if (CustomServiceObject.OnInit())
			{
				CustomServiceObject.m_bIsRunning = TRUE;
				CustomServiceObject.Run();
			}
#endif
		}
	}

    // When we get here, the service has been stopped
    return CustomServiceObject.m_Status.dwWin32ExitCode;
}
