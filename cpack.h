/*
  cpack - Pack Wii U NUS content files (encryption support)

  Copyright (C) 2024

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
*/

#ifndef CPACK_H
#define CPACK_H

/*
  cpack.h - Re-encrypt Wii U NUS .app.dec files back to .app
*/

int pack_title(const char* input_dir, const char* output_dir);

#endif // CPACK_H