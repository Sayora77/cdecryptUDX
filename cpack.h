#ifndef CPACK_H
#define CPACK_H

/*
  cpack.h - Re-encrypt Wii U NUS .app.dec files back to .app
*/

// Re-encrypts all .app.dec files in dir back to .app, verifies each against
// its .app.md5 sidecar, and on success deletes the .app.dec and .app.md5.
int pack_title(const char* dir);

#endif // CPACK_H