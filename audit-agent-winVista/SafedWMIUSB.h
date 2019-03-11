#include <comdef.h>
#include <Wbemidl.h>

#define USB_EVENT  10000
#define USB_INSERTED 18
#define USB_REMPOVED 19
#define USB_MODIFIED 20
//#define WMIFilter " and TargetInstance.Description=\'USB Mass Storage Device\' "
#define WMIFilter ""


int StartWMIUSBThread(HANDLE event);
void GetInfoWMI(HANDLE event);
int TerminateWMI();
int InitWMI(char* WMIcondition);
int TerminateWMIUSBThread();
BOOL isNotClosedWMIUSBThread();
int PutWMIUSBToQueue(char* msg, char* Time, DWORD EventID);