#pragma once

#include <string>
#include <vector>

extern std::vector<void*> SegmentList;

typedef struct
{
    DWORD       Start;
    DWORD       Size;
    DWORD       Flags;
    std::string Name;
} SegmentInfo, *PSegmentInfo;

int __fastcall Adr2Pos(DWORD adr);
