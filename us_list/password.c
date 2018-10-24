#include <stdio.h>

int password_encode(char *password, char *buf)
{
	while(*password)
	{
		if(*password >= 80)
			*(buf ++) = *password - 47;
		else
			*(buf ++) = *password + 47;
		password ++;
	}
	*(buf ++) = '\0';
	return 1;
}

int main()
{
	char a[100], b[100];
	scanf("%s", a);
	password_encode(a, b);
	printf("%s\n", b);
}