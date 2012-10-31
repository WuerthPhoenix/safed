void	decodeurl(char *pEncoded);
int		hex2int(char *pChars);
int		InitWebServer(unsigned short, char *, char *);
int		StartThread(HANDLE event);
void	ListenThread(HANDLE event);
int		HandleConnect(HANDLE event);
int		CloseWebServer();
void	RequestAuth(char *HTTPOutputBuffer,int size);
BOOL	MatchAuth(char *AuthStart);
BOOL	AuthorisedSource(char *address);
char *	GetNextArgument(char *source,char *destvar,int varlength,char *destval,int vallength);
int		base64decode(char *dest, char *src);
int		base64encode(char *dest, char *src, int len);

