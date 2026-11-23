#include "small_font.h"
#include "assets/font12/font12_data.h"
const h1_font16 qq_font12={sizeof qq12_cp/sizeof qq12_cp[0],qq12_cp,qq12_width,qq12_rows};
const h1_font16 qq_title_font16={sizeof qq16_title_cp/sizeof qq16_title_cp[0],qq16_title_cp,qq16_title_width,qq16_title_rows};
unsigned qq_font_line_height(unsigned cp)
{
    unsigned lo=0,count=sizeof qq12_fallback_cp/sizeof qq12_fallback_cp[0],hi=count;
    while(lo<hi){unsigned mid=(lo+hi)/2;if(qq12_fallback_cp[mid]<cp)lo=mid+1;else hi=mid;}
    return lo<count&&qq12_fallback_cp[lo]==cp?18:14;
}
