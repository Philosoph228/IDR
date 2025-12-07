#include "precomp.hpp"
#include "Util.hpp"

int __fastcall Adr2Pos(DWORD adr)
{
    int     ofs = 0;
    for (int n = 0; n < SegmentList->Count; n++)
    {
        PSegmentInfo segInfo = (PSegmentInfo)SegmentList->Items[n];
        if (segInfo->Start <= adr && adr < segInfo->Start + segInfo->Size)
        {
            if (segInfo->Flags & 0x80000)
                return -1;
            return ofs + (adr - segInfo->Start);
        }
        if (!(segInfo->Flags & 0x80000))
            ofs += segInfo->Size;
    }
    return -2;
}
