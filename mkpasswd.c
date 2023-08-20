/* simple password generator by Nelson Minar (minar@reed.edu)
 * copyright 1991, all rights reserved.
 * You can use this code as long as my name stays with it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

extern char *getpass ();
char phpass[1024];

int main (argc, argv)
     int argc;
     char *argv[];
{
  char *crypt ();
  static char saltChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
  char salt[3];
  char *plaintext;
  int p, s;

  srandom (time (0));		/* may not be the BEST salt, but its close */
  salt[0] = saltChars[random () % 64];
  salt[1] = saltChars[random () % 64];
  salt[2] = 0;
  s = 0;
  for (p = 1; p < argc; p++)
  {
    switch (argv[p][0])
    {
      case '-':
	{
	  if (argv[p][1] == 's')
	    s = 1;
	  break;
	}
      default:
	{
	  salt[0] = argv[p][0];
	  salt[1] = argv[p][1];
	  salt[2] = '\0';
	  if ((strchr (saltChars, salt[0]) == NULL) || (strchr (saltChars, salt[1]) == NULL))
	  {
	    if (!s)
	      fprintf (stderr, "illegal salt %s\n", salt);
	    exit (1);
	  }
	}
    }
  }

  if (s == 1)
  {
    fgets (phpass, 1024, stdin);
    for (p = 0; phpass[p]; p++)
    {
      if (p >= 1023) {
	phpass[p] = '\0';
	break;
      }
      if (phpass[p] == '\n')
	phpass[p] = '\0';
    }
    plaintext = phpass;
  }
  else
  {
    plaintext = getpass ("plaintext: ");
  }
  printf ("%s\n", crypt (plaintext, salt));
  return 0;
}

