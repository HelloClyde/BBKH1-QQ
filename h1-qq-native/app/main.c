#include "qq.h"
#include "qr_png.h"
#include "avatars.h"
#include "firmware.h"
#include "h1_draw.h"
#include "small_font.h"
#include "h1_media_runtime.h"
#include "h1_sdk.h"
#include "h1_text_input.h"
#include "h1_touch.h"
#include "transport.h"

#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "assets/qq_icon.h"
#include "assets/skin2008/skin.h"
#include "assets/idle2008/idle.h"
#include "assets/login2008/login.h"
#include "assets/menu2008/menu.h"

enum { SIDE = 154, LIST_Y = 111, ROW_H = 26, VISIBLE = 5, HISTORY_Y = 64, HISTORY_H = 138, HISTORY_PAD = 8, HISTORY_VIEW_H = HISTORY_H - HISTORY_PAD };
enum { PICK_ROW = 1000, SELECT_FRIENDS = 500, SELECT_GROUPS, SEND_TOUCH, REFRESH_TOUCH, SEARCH_TOUCH, CLEAR_SEARCH, SELECT_RECENT, MENU_TOUCH, EXIT_TOUCH, LIST_SCROLL_UP, LIST_SCROLL_DOWN, LIST_SCROLL_PAGE_UP, LIST_SCROLL_PAGE_DOWN, SETTINGS_TOUCH, SETTINGS_BACK, CLEAR_HISTORY_TOUCH, CONFIRM_CLEAR_HISTORY, CANCEL_CLEAR_HISTORY };
#define RGB(n) ((uint16_t)((((n) >> 19) & 31) << 11 | (((n) >> 10) & 63) << 5 | (((n) >> 3) & 31)))
#define INK RGB(0x142a3a)
#define SUB RGB(0x547588)
#define BLUE RGB(0x277fa9)
#define LINE RGB(0x93c7dd)
#define PAPER RGB(0xffffff)
#define TINT RGB(0xd8f0fa)
#define BG RGB(0xb2dfef)

static uint16_t pixels[480 * 272];
static h1_canvas canvas = {pixels, 480, 272, 480, 0, 272, &qq_font12};
static qq_config config;
static qq_people people[3];
static uint8_t recent_kind[QQ_PEOPLE_MAX];
static qq_messages history;
static qq_person self, peer;
static char draft[QQ_TEXT_MAX];
static const char *notice = "正在启动…";
static char notice_text[256];
static unsigned group, peer_group, selected, first, offset, list_loaded[3];
static unsigned list_loading[3],list_error[3];
static int config_ok, peer_open, list_focus = 1, busy, background, closing, pending, dirty = 1;
static int has_usb, has_context, last_connected, panic_code;
static int pen_key,pen_active,pen_start,pen_last,pen_x,pen_drag,pen_area;
static uint32_t clock_base,frames,pen_sample,shown_revision,shown_avatar_revision,notice_until;
static unsigned list_pixel;
static int service_error;
static uint8_t qr_pixels[200*200];
static unsigned qr_width,qr_height;
static enum qq_login_phase login_phase;
static int login_refresh;
static int rows[QQ_PEOPLE_MAX+QQ_CATEGORIES_MAX];
static unsigned row_count,matched_count;
static uint8_t collapsed[3][QQ_CATEGORIES_MAX];
static char query[3][65];
static int menu_open;
static int selection_visible;
static int interactive_wait;
static int settings_open,history_warned;
static uint32_t loading_tick;
static jmp_buf panic_return;
int qq_cancel;
volatile unsigned qq_usb_handoff;
static void act(int key);

uint32_t qq_time(void) { return clock_base + h1_timer_read_ms(); }
uint32_t h1ns_time_ms(void) { return qq_time(); }
void h1ns_panic(int code) { panic_code = code; longjmp(panic_return, 1); }

/* A small wrapper also provides the modeled input boundary. */
__attribute__((noinline)) int qq_edit_text(char *out, unsigned capacity)
{
    return h1_input_text(out, capacity, "QQ\xc1\xc4\xcc\xec");
}
__attribute__((noinline)) int qq_edit_search(char *out,unsigned capacity)
{
    return h1_input_text(out,capacity,"QQ\xcb\xd1\xcb\xf7");
}

static int open_gui(void)
{
    typedef int (*open_fn)(void);
    has_context = ((open_fn)h1_runtime_entry(h1_runtime_table(H1_RUNTIME_GUI_TABLE_SLOT), 0x84c))();
    return has_context;
}

static void close_gui(void)
{
    if (!has_context) return;
    typedef void (*close_fn)(void);
    ((close_fn)h1_runtime_entry(h1_runtime_table(H1_RUNTIME_GUI_TABLE_SLOT), 0x850))();
    has_context = 0;
}

static void inform(const char *message)
{
    unsigned n=(unsigned)strlen(message);if(n>=sizeof notice_text)n=sizeof notice_text-1;memmove(notice_text,message,n);notice_text[n]=0;notice=notice_text;
    notice_until=qq_time()+4000;
    dirty = 1;
}

static void box(int x, int y, int w, int h, uint16_t color)
{
    h1_draw_rect(&canvas, x, y, w, h, color);
}

static void label(const char *s, int x, int y, int end, uint16_t color)
{
    h1_draw_ellipsis(&canvas, s, x, y+(canvas.font==&qq_font12), end, color);
}

static void button(const char *s, int x, int y, int w, int h, int active)
{
    h1_draw_round(&canvas,x,y,w,h,3,RGB(0x559ac1));h1_draw_round(&canvas,x+1,y+1,w-2,h-2,2,active?PAPER:RGB(0xa8d7ef));
    box(x+2,y+2,w-4,(h-3)/2,active?PAPER:RGB(0xe4f6ff));box(x+2,y+2,w-4,1,PAPER);
    box(x+3,y+h-2,w-6,1,active?RGB(0xc9e7f5):RGB(0x6fb0d3));
    label(s, x + (w - h1_draw_width(canvas.font, s)) / 2, y + (h - 16) / 2,
          x + w, INK);
}

static void gradient(int x,int y,int w,int h,unsigned a,unsigned b)
{
    for(int i=0;i<h;++i){unsigned r=((a>>16&255)*(h-1-i)+(b>>16&255)*i)/(h-1),g=((a>>8&255)*(h-1-i)+(b>>8&255)*i)/(h-1),v=((a&255)*(h-1-i)+(b&255)*i)/(h-1);box(x,y+i,w,1,RGB((r<<16)|(g<<8)|v));}
}
static void sprite(int x,int y,const uint32_t *src,unsigned size)
{
    for(unsigned j=0;j<size;++j){int py=y+(int)j;if(py<canvas.clip_top||py>=canvas.clip_bottom||py<0||py>=272)continue;
        for(unsigned i=0;i<size;++i){int px=x+(int)i;if(px<0||px>=480)continue;uint32_t c=src[j*size+i];unsigned a=c>>24;if(!a)continue;uint16_t old=pixels[py*480+px];unsigned r=((c>>16&255)*a+((old>>11)*255/31)*(255-a))/255,g=((c>>8&255)*a+((old>>5&63)*255/63)*(255-a))/255,b=((c&255)*a+((old&31)*255/31)*(255-a))/255;pixels[py*480+px]=RGB((r<<16)|(g<<8)|b);}}
}
static void bevel(int x,int y,int w,int h)
{box(x,y,w,h,LINE);box(x+1,y+1,w-2,h-2,PAPER);box(x+2,y+2,w-4,1,RGB(0x779daf));}
static void person_avatar(int x,int y,unsigned size,int troop,const char *id)
{
    if(y+(int)size<=canvas.clip_top||y>=canvas.clip_bottom)return;
    h1_draw_round(&canvas,x-2,y-2,(int)size+4,(int)size+4,2,RGB(0x76a9c6));box(x-1,y-1,(int)size+2,(int)size+2,PAPER);
    const uint16_t *source;unsigned w,h;
    if(!qq_avatar_peek(troop,id,&source,&w,&h)){box(x,y,(int)size,(int)size,RGB(0xe9f7fd));if(troop)sprite(x+((int)size-16)/2,y+((int)size-16)/2,qq08_group_16,16);else sprite(x+((int)size-16)/2,y+((int)size-16)/2,qq_icon_16,16);return;}
    for(unsigned j=0;j<size;++j){int py=y+(int)j;if(py<canvas.clip_top||py>=canvas.clip_bottom)continue;
        for(unsigned i=0;i<size;++i)pixels[py*480+x+i]=source[(j*h/size)*w+i*w/size];}
}
static void frame(void)
{
    gradient(0,0,480,272,0x82cef0,0x68b7de);
    for(unsigned y=0;y<60;++y)memcpy(pixels+y*480,qq08_header+y*480,480*2);
    box(1,1,478,1,PAPER);box(1,21,478,1,RGB(0x3a95c4));
    for(unsigned y=0;y<22;++y){memcpy(pixels+y*480,qq08_brand+y*396,396*2);box(396,(int)y,84,1,qq08_brand[y*396+395]);}
    button("",451,2,26,18,0);h1_draw_line(&canvas,459,6,469,15,RGB(0xa44730));h1_draw_line(&canvas,469,6,459,15,RGB(0xa44730));
    sprite(426,3,qq08_refresh_16,16);
}
static void tab(const char *text,int x,int w,int active,const uint32_t *image)
{button("",x,87,w,22,active);sprite(x+3,90,image,16);label(text,x+21,91,x+w-1,INK);}
static void idle_panel(void)
{for(unsigned y=0;y<250;++y)memcpy(pixels+(y+22)*480+SIDE,qq08_idle+y*326,326*2);}
static void loading_spinner(int x,int y)
{
    static const int dx[8]={0,5,7,5,0,-5,-7,-5},dy[8]={-7,-5,0,5,7,5,0,-5};unsigned phase=qq_time()/120%8;
    for(unsigned i=0;i<8;++i){unsigned fade=((i+8-phase)%8)*20;unsigned c=((35+fade)<<16)|((117+fade/2)<<8)|(168+fade/3);box(x+dx[i]-1,y+dy[i]-1,3,3,RGB(c));}
}
static void list_scrollbar(void)
{
    int x=SIDE-10,track=VISIBLE*ROW_H-24;box(x,LIST_Y,7,VISIBLE*ROW_H,RGB(0xe4f4fb));
    button("",x,LIST_Y,7,11,0);button("",x,LIST_Y+VISIBLE*ROW_H-11,7,11,0);
    h1_draw_line(&canvas,x+1,LIST_Y+6,x+3,LIST_Y+3,BLUE);h1_draw_line(&canvas,x+3,LIST_Y+3,x+5,LIST_Y+6,BLUE);
    int bottom=LIST_Y+VISIBLE*ROW_H-5;h1_draw_line(&canvas,x+1,bottom-2,x+3,bottom+1,BLUE);h1_draw_line(&canvas,x+3,bottom+1,x+5,bottom-2,BLUE);
    if(row_count>VISIBLE){unsigned h=(unsigned)track*VISIBLE/row_count;if(h<12)h=12;int y=LIST_Y+12+(int)((first*ROW_H+list_pixel)*((unsigned)track-h)/((row_count-VISIBLE)*ROW_H));button("",x,y,7,(int)h,0);}
}
static unsigned fold_ascii(unsigned c){return c>='A'&&c<='Z'?c+32:c;}
static int contains(const char *text,const char *term)
{
    if(!*term)return 1;
    for(;*text;++text){const unsigned char *a=(const unsigned char *)text,*b=(const unsigned char *)term;while(*a&&*b&&fold_ascii(*a)==fold_ascii(*b)){++a;++b;}if(!*b)return 1;}return 0;
}
static int matches(const qq_person *p)
{
    return contains(p->name,query[group])||contains(p->nick,query[group])||contains(p->id,query[group]);
}
static void rebuild_rows(int choose_contact)
{
    qq_people *list=&people[group];uint8_t seen[256]={0};unsigned ids[256],count=0;row_count=matched_count=0;
    for(unsigned i=0;i<list->category_count;++i){unsigned id=list->categories[i].id;if(id<256&&!seen[id]){seen[id]=1;ids[count++]=id;}}
    for(unsigned i=0;i<list->count;++i){unsigned id=list->items[i].category&255;if(!seen[id]){seen[id]=1;ids[count++]=id;}}
    for(unsigned i=0;i<count;++i){unsigned id=ids[i],hits=0;for(unsigned j=0;j<list->count;++j)if(list->items[j].category==id&&matches(&list->items[j]))++hits;
        matched_count+=hits;if(query[group][0]&&!hits)continue;rows[row_count++]=-(int)id-1;
        if(!collapsed[group][id]||query[group][0])for(unsigned j=0;j<list->count;++j)if(list->items[j].category==id&&matches(&list->items[j]))rows[row_count++]=(int)j;
    }
    list_pixel=0;if(choose_contact){selected=first=0;for(unsigned i=0;i<row_count;++i)if(rows[i]>=0){selected=i;break;}}
    if(selected>=row_count)selected=row_count?row_count-1:0;
    if(first>selected)first=selected;if(selected>=first+VISIBLE)first=selected-VISIBLE+1;dirty=1;
}
static void category_label(unsigned id,char out[112])
{
    qq_people *list=&people[group];unsigned hits=0;const char *name=NULL;char fallback[48];
    for(unsigned i=0;i<list->category_count;++i)if(list->categories[i].id==id){name=list->categories[i].name;break;}
    if(!name||!*name){if(!id)name="我的好友";else{snprintf(fallback,sizeof fallback,"未命名分组 %u",id);name=fallback;}}
    for(unsigned i=0;i<list->count;++i)if(list->items[i].category==id&&matches(&list->items[i]))++hits;
    snprintf(out,112,"%s (%u)",name,hits);
}

/* The drawing and measurement use identical UTF-8 wrapping. */
static const char *message_line(const char *text, int x, int y, int end, int draw,unsigned *height)
{
    while (*text && *text != '\n') {
        const char *next = text;
        int cp = h1_utf8_next(&next);
        int width = (int)h1_draw_advance(canvas.font, (unsigned)cp);
        if (x + width > end) break;
        unsigned line=qq_font_line_height((unsigned)cp);if(line>*height)*height=line;
        if (draw) h1_draw_glyph(&canvas, (unsigned)cp, x, y, end, INK);
        x += width;
        text = next;
    }
    return *text == '\n' ? text + 1 : text;
}

static unsigned chat_height(int draw, int top)
{
    for(unsigned i=0;i<history.count;++i){const qq_message *m=&history.items[i];
        if(draw){char stamp[8];unsigned local=(m->time+8u*3600u)%86400u;snprintf(stamp,sizeof stamp,"%02u:%02u",local/3600,local/60%60);person_avatar(SIDE+7,top,16,0,m->sender_id);label(m->sender,SIDE+28,top,423,m->mine?RGB(0x338500):RGB(0x003acc));label(stamp,432,top,476,SUB);}
        top+=18;for(const char *text=m->text;*text;){unsigned height=14;text=message_line(text,SIDE+9,top,470,draw,&height);top+=(int)height;}top+=4;
    }return (unsigned)top;
}

static unsigned max_offset(void)
{
    unsigned height = chat_height(0, 0);
    return height > HISTORY_VIEW_H ? height - HISTORY_VIEW_H : 0;
}

static void paint(void)
{
    if (!has_context) return;
    frame();
    /* One compact profile band per column, matching the approved wide design. */
    bevel(2,23,SIDE-4,39);if(peer_open)bevel(SIDE+1,23,324,39);
    for(int y=25;y<60;++y){memcpy(pixels+y*480+4,qq08_header+(y-23)*480+4,(SIDE-8)*2);if(peer_open)memcpy(pixels+y*480+SIDE+3,qq08_header+(y-23)*480+SIDE+3,320*2);}
    person_avatar(7,28,28,0,self.id);label(self.name[0]?self.name:"QQ",62,33,SIDE-10,INK);
    if(self.id[0]&&!service_error)sprite(42,33,qq08_online_16,16);
    if(peer_open){person_avatar(SIDE+8,28,28,peer_group,peer.id);label(peer.name,SIDE+43,33,471,INK);}

    bevel(3,64,SIDE-6,21);sprite(7,66,qq08_search_16,16);label(query[group][0]?query[group]:"搜索",27,66,SIDE-23,query[group][0]?INK:SUB);
    if(query[group][0])label("×",SIDE-20,66,SIDE-5,SUB);
    tab("好友",3,49,group==0,qq_icon_16);tab("群",53,47,group==1,qq08_group_16);tab("最近",101,50,group==2,qq08_recent_16);
    bevel(3,LIST_Y-1,SIDE-6,VISIBLE*ROW_H+2);qq_people *list=&people[group];
    canvas.clip_top=LIST_Y;canvas.clip_bottom=LIST_Y+VISIBLE*ROW_H;
    for(unsigned row=0;row<VISIBLE+1&&row+first<row_count;++row){unsigned i=first+row;int item=rows[i],y=LIST_Y+(int)row*ROW_H-(int)list_pixel;
        if(item<0){unsigned id=(unsigned)(-item-1);char title[112];category_label(id,title);gradient(5,y,SIDE-12,ROW_H-1,0xf4fbff,0xd6ebf7);
            if(collapsed[group][id]&&!query[group][0]){h1_draw_line(&canvas,10,y+8,14,y+12,BLUE);h1_draw_line(&canvas,14,y+12,10,y+16,BLUE);}
            else{h1_draw_line(&canvas,9,y+10,13,y+14,BLUE);h1_draw_line(&canvas,13,y+14,17,y+10,BLUE);}label(title,21,y+5,SIDE-12,INK);
        }else{if(i==selected&&(peer_open||selection_visible))gradient(5,y,SIDE-12,ROW_H-1,0xfff8d8,0xffedaf);person_avatar(9,y+2,22,group==2?recent_kind[item]:(int)group,list->items[item].id);label(list->items[item].name,36,y+5,SIDE-12,INK);}
    }
    list_scrollbar();
    canvas.clip_top=0;canvas.clip_bottom=272;
    if(!row_count){if(list_loading[group]){loading_spinner(76,153);label("加载中…",51,171,SIDE-9,SUB);}
        else label(query[group][0]?"无结果":group==2?"暂无聊天":list_error[group]?"加载失败":list_loaded[group]?"列表为空":"未加载",10,148,SIDE-9,SUB);}
    gradient(3,245,SIDE-6,25,0xc0eafa,0x77bddd);box(3,245,SIDE-6,1,PAPER);button("",5,246,35,24,menu_open);sprite(8,248,qq08_menu_penguin_20,20);
    h1_draw_line(&canvas,30,256,33,259,BLUE);h1_draw_line(&canvas,33,259,36,256,BLUE);
    sprite(49,249,qq08_search_20,20);sprite(86,249,qq08_recent_20,20);sprite(122,249,qq08_refresh_20,20);
    for(int x=43;x<120;x+=36){box(x,249,1,17,RGB(0x69b2d7));box(x+1,249,1,17,PAPER);}
    if(!peer_open)idle_panel();else{
    bevel(SIDE+2,HISTORY_Y-1,323,HISTORY_H+2);
    canvas.clip_top=HISTORY_Y+HISTORY_PAD-2;canvas.clip_bottom=HISTORY_Y+HISTORY_H;
    if(history.count)chat_height(1,HISTORY_Y+HISTORY_PAD-(int)offset);

    canvas.clip_top=0;canvas.clip_bottom=272;
    unsigned limit=max_offset();if(limit){unsigned h=HISTORY_H*HISTORY_VIEW_H/(limit+HISTORY_VIEW_H);if(h<12)h=12;box(472,HISTORY_Y,3,HISTORY_H,RGB(0xe5f3fa));box(472,HISTORY_Y+(int)(offset*(HISTORY_H-h)/limit),3,(int)h,RGB(0x7db9d3));}
    bevel(SIDE+2,205,323,38);if(peer_open){if(draft[0])label(draft,SIDE+10,213,468,INK);else box(SIDE+10,211,1,18,INK);}
    gradient(SIDE+2,245,323,25,0xc8edf9,0x88c5e5);button("发送",407,245,69,25,draft[0]!=0);
    }
    /* Quiet normal states; only actionable failures and short send feedback
     * occupy the footer. The detailed diagnostic remains in the log. */
    if((int32_t)(notice_until-qq_time())>0&&(service_error||strstr(notice,"失败")||strstr(notice,"拒绝")||strstr(notice,"草稿")||strstr(notice,"未确认")||strstr(notice,"无法")||strstr(notice,"过期")||strstr(notice,"离线")||strstr(notice,"清除")||!self.id[0]))label(notice,SIDE+8,250,401,RGB(0x8e3f26));
    if(menu_open){bevel(4,143,112,101);button("刷新",7,146,106,22,0);button("搜索",7,170,106,22,0);button("设置",7,194,106,22,0);button("退出",7,218,106,22,0);}
    if(settings_open){bevel(112,68,256,136);label(settings_open==2?"清除历史会话":"设置",128,80,352,INK);
        if(settings_open==1){button("清除历史会话",128,106,224,28,0);button("返回",248,164,104,26,0);}
        else{label("删除本机聊天记录和最近会话？",128,113,352,INK);button("取消",128,164,100,26,0);button("清除",252,164,100,26,0);}}
    typedef volatile uint32_t *(*buffer_fn)(uint16_t *, void *);
    uint16_t info[6] = {0};
    volatile uint32_t *out = ((buffer_fn)h1_runtime_entry(h1_runtime_table(H1_RUNTIME_GUI_TABLE_SLOT), 0x8f4))(info, NULL);
    if (out && info[1] == 480 && info[2] == 272 && info[3] == 1920 && info[5] == 32) {
        for (unsigned i = 0; i < 480 * 272; ++i) {
            unsigned c = pixels[i];
            out[i] = ((c & 0xf800) << 8) | ((c & 0x7e0) << 5) | ((c & 31) << 3);
        }
        ++frames;
    }
    dirty = 0;
}

int qq_login_refresh_requested(void){int wanted=login_refresh;login_refresh=0;return wanted;}
int qq_login_display(enum qq_login_phase phase,const uint8_t *png,unsigned size,const char *status)
{
    if(!has_context)return !png;int valid=1;
    if(interactive_wait&&phase==QQ_LOGIN_REGISTER&&login_phase==QQ_LOGIN_NONE&&!png&&self.id[0]){inform(status);paint();return 1;}
    login_phase=phase;
    if(phase!=QQ_LOGIN_WAIT&&phase!=QQ_LOGIN_CONFIRM)qr_width=qr_height=0;
    if(png&&!qq_qr_png(png,size,qr_pixels,&qr_width,&qr_height)){qr_width=qr_height=0;valid=0;}
    memcpy(pixels,qq08_login_background,sizeof pixels);
    const char *title=phase==QQ_LOGIN_WAIT||phase==QQ_LOGIN_CONFIRM?"手机 QQ 扫码":"登录 QQ";
    const char *state=!valid?"二维码无法显示":phase==QQ_LOGIN_PREPARE?"准备中…":phase==QQ_LOGIN_WAIT?"等待扫码":phase==QQ_LOGIN_CONFIRM?"请在手机确认":"正在登录…";
    label(title,316-h1_draw_width(canvas.font,title)/2,32,425,INK);
    if(qr_width&&qr_width<=160&&qr_height<=160){unsigned x0=316-qr_width/2,y0=140-qr_height/2;box((int)x0-6,(int)y0-6,(int)qr_width+12,(int)qr_height+12,PAPER);
        for(unsigned y=0;y<qr_height;++y)for(unsigned x=0;x<qr_width;++x)pixels[(y0+y)*480+x0+x]=qr_pixels[y*qr_width+x]?PAPER:0;
    }
    int refresh=phase==QQ_LOGIN_WAIT||phase==QQ_LOGIN_CONFIRM;int width=h1_draw_width(canvas.font,state),x=316-(width+(refresh?32:0))/2;
    label(state,x,240,x+width+1,INK);if(refresh)sprite(x+width+12,238,qq08_refresh_20,20);
    typedef volatile uint32_t *(*buffer_fn)(uint16_t *,void *);uint16_t info[6]={0};
    volatile uint32_t *out=((buffer_fn)h1_runtime_entry(h1_runtime_table(H1_RUNTIME_GUI_TABLE_SLOT),0x8f4))(info,NULL);
    if(out&&info[1]==480&&info[2]==272&&info[3]==1920&&info[5]==32)for(unsigned i=0;i<480*272;++i){unsigned c=pixels[i];out[i]=((c&0xf800)<<8)|((c&0x7e0)<<5)|((c&31)<<3);}
    return valid;
}

static void scroll(int delta)
{
    int moved = (int)offset + delta;
    unsigned limit = max_offset();
    offset = moved < 0 ? 0 : (unsigned)moved > limit ? limit : (unsigned)moved;
    dirty = 1;
}
static void scroll_list(int delta)
{
    selection_visible=1;unsigned limit=row_count>VISIBLE?(row_count-VISIBLE)*ROW_H:0;int next=(int)(first*ROW_H+list_pixel)+delta;
    unsigned position=next<0?0:(unsigned)next>limit?limit:(unsigned)next;first=position/ROW_H;list_pixel=position%ROW_H;
    if(selected<first)selected=first;if(selected>=first+VISIBLE)selected=first+VISIBLE-1;list_focus=1;dirty=1;
}

static int touch_key(int x,int y)
{
    if(login_phase!=QQ_LOGIN_NONE){if(y<22&&x>=451)return EXIT_TOUCH;return (login_phase==QQ_LOGIN_WAIT||login_phase==QQ_LOGIN_CONFIRM)&&x>=334&&x<388&&y>=234&&y<265?REFRESH_TOUCH:0;}
    if(settings_open){if(x>=128&&x<352){if(settings_open==1&&y>=106&&y<134)return CLEAR_HISTORY_TOUCH;if(y>=164&&y<190)return settings_open==1?SETTINGS_BACK:x<228?CANCEL_CLEAR_HISTORY:x>=252?CONFIRM_CLEAR_HISTORY:0;}return 0;}
    if(menu_open){if(x<118&&y>=143&&y<244)return y<169?REFRESH_TOUCH:y<193?SEARCH_TOUCH:y<217?SETTINGS_TOUCH:EXIT_TOUCH;return MENU_TOUCH;}
    if(y<22){if(x>=451)return EXIT_TOUCH;if(x>=419)return REFRESH_TOUCH;return 0;}
    if(x<SIDE){
        if(y>=64&&y<85)return x>=SIDE-22&&query[group][0]?CLEAR_SEARCH:SEARCH_TOUCH;
        if(y>=87&&y<110)return x<53?SELECT_FRIENDS:x<101?SELECT_GROUPS:SELECT_RECENT;
        if(y>=245)return x<39?MENU_TOUCH:x<78?SEARCH_TOUCH:x<114?SELECT_RECENT:REFRESH_TOUCH;
        if(y>=LIST_Y&&y<LIST_Y+VISIBLE*ROW_H&&x>=SIDE-12){if(row_count<=VISIBLE)return 0;return y<LIST_Y+12?LIST_SCROLL_UP:y>=LIST_Y+VISIBLE*ROW_H-12?LIST_SCROLL_DOWN:y<LIST_Y+VISIBLE*ROW_H/2?LIST_SCROLL_PAGE_UP:LIST_SCROLL_PAGE_DOWN;}
        if(y>=LIST_Y&&y<LIST_Y+VISIBLE*ROW_H){unsigned row=first+(unsigned)(y-LIST_Y+(int)list_pixel)/ROW_H;if(row<row_count)return PICK_ROW+(int)row;}
    }else if(peer_open){
        if(y>=205&&y<243&&peer_open)return H1_KEY_I;
        if(y>=245&&x>=407&&peer_open)return SEND_TOUCH;
    }return 0;
}

static void queue(int key)
{
    if (!key) return;
    if(login_phase!=QQ_LOGIN_NONE){
        if(key==EXIT_TOUCH||key==H1_KEY_ESCAPE||key==H1_KEY_BACK){qq_cancel=1;pending=EXIT_TOUCH;}
        else if((key==H1_KEY_R||key==REFRESH_TOUCH)&&(login_phase==QQ_LOGIN_WAIT||login_phase==QQ_LOGIN_CONFIRM))login_refresh=1;
        return;
    }
    if(settings_open){if(key==H1_KEY_ESCAPE||key==H1_KEY_BACK)key=settings_open==2?CANCEL_CLEAR_HISTORY:SETTINGS_BACK;
        if(key!=SETTINGS_BACK&&key!=CLEAR_HISTORY_TOUCH&&key!=CONFIRM_CLEAR_HISTORY&&key!=CANCEL_CLEAR_HISTORY)return;}
    if(interactive_wait){
        switch(key){
        case H1_KEY_LEFT:case H1_KEY_RIGHT:case H1_KEY_UP:case H1_KEY_DOWN:
        case H1_KEY_PAGE_UP:case H1_KEY_PAGE_DOWN:case H1_KEY_Z:case H1_KEY_X:
        case LIST_SCROLL_UP:case LIST_SCROLL_DOWN:case LIST_SCROLL_PAGE_UP:case LIST_SCROLL_PAGE_DOWN:
        case H1_KEY_DELETE:case H1_KEY_ESCAPE:case H1_KEY_BACK:case EXIT_TOUCH:
        case MENU_TOUCH:case CLEAR_SEARCH:
            act(key);if(closing)qq_cancel=1;return;
        default:break;
        }
        if(key>=PICK_ROW&&(unsigned)(key-PICK_ROW)<row_count&&rows[key-PICK_ROW]<0){act(key);return;}
        /* Keep a single in-flight request; repeated refresh taps are coalesced. */
        if(!background&&(key==H1_KEY_R||key==REFRESH_TOUCH))return;
    }
    if(pending)return;
    if (busy && !interactive_wait) {
        if (key == H1_KEY_ESCAPE || key == H1_KEY_BACK || key==EXIT_TOUCH){qq_cancel=1;if(key==EXIT_TOUCH)pending=key;}
        return;
    }
    /* Foreground network actions wait for the current background request.
     * A local navigation key must never tear down the QQ TCP session. */
    pending = key;
}

static void collect(void)
{
    for (int i = 0; i < 24; ++i) {
        int event, key;
        h1_event_fetch(&event, &key);
        if (event < 0) break;
        if (event == H1_EVENT_KEY_DOWN) { pen_active=0;queue(key); continue; }
        if (event != H1_EVENT_TOUCH_DOWN && event != H1_EVENT_TOUCH_MOVE && event != H1_EVENT_TOUCH_UP) continue;
        h1_u16 x = 0, y = 0;
        int valid = h1_touch_position(&x, &y);
        if(event==H1_EVENT_TOUCH_DOWN&&valid){pen_active=1;pen_drag=0;pen_key=touch_key(x,y);pen_start=pen_last=y;pen_x=x;pen_sample=qq_time();
            pen_area=login_phase!=QQ_LOGIN_NONE||settings_open||menu_open?0:x<SIDE&&y>=LIST_Y&&y<LIST_Y+VISIBLE*ROW_H?1:peer_open&&x>=SIDE&&y>=HISTORY_Y&&y<HISTORY_Y+HISTORY_H?2:0;
        }else if(pen_active&&(event==H1_EVENT_TOUCH_MOVE||event==H1_EVENT_TOUCH_UP)){
            if(valid){int distance=(int)y-pen_start;if(distance>7||distance< -7)pen_drag=1;
                if(pen_drag&&(!busy||interactive_wait)){if(pen_area==1)scroll_list(pen_last-(int)y);else if(pen_area==2)scroll(pen_last-(int)y);}pen_last=y;pen_x=x;}
            if(event==H1_EVENT_TOUCH_UP){pen_active=0;if(!pen_drag&&pen_key==touch_key(valid?x:pen_x,valid?y:pen_last))queue(pen_key);pen_key=pen_area=0;}
        }
    }
    /* V1.41 may only enqueue DOWN/UP. Sample calibrated coordinates while held. */
    if(pen_active&&pen_area&&qq_time()-pen_sample>=16){h1_u16 x,y;pen_sample=qq_time();if(h1_touch_position(&x,&y)){
        int distance=(int)y-pen_start;if(distance>7||distance< -7)pen_drag=1;
        if(pen_drag&&(!busy||interactive_wait)){if(pen_area==1)scroll_list(pen_last-(int)y);else scroll(pen_last-(int)y);}pen_last=y;pen_x=x;
    }}
}

void qq_idle(void *unused)
{
    (void)unused;
    h1net_transport_poll();
    collect();
    if(list_loading[group]&&qq_time()-loading_tick>=120){loading_tick=qq_time();dirty=1;}
    if((interactive_wait||list_loading[group])&&login_phase==QQ_LOGIN_NONE&&dirty&&has_context)paint();
    fw_delay(1);
}

static void load_config(void)
{
    config.native=1;config_ok=1;
    inform("连接 ESP32 后扫码登录 QQ");
}

static const char *error_text(enum qq_result result)
{
    if(qq_last_error[0])return qq_last_error;
    switch (result) {
    case QQ_OFFLINE: return "未连接 ESP32-S3";
    case QQ_FIRMWARE: return "ESP32 固件需要 TCP 支持";
    case QQ_AUTH: return "登录失效，请按 R 重新扫码";
    case QQ_HTTP: return "QQ 公共密钥获取失败";
    case QQ_TOO_LARGE: return "QQ 返回数据超出容量";
    case QQ_RESPONSE: return "QQ 返回格式无法读取";
    case QQ_REJECTED: return "QQ 服务拒绝请求，请检查登录";
    case QQ_CANCELLED: return "已取消";
    default: return "连接失败，请检查 Wi-Fi";
    }
}

static void start(const char *message, int automatic)
{
    qq_cancel = 0;
    qq_last_error[0]=0;
    busy = 1;
    background = automatic;
    interactive_wait = automatic;
    if (!automatic) { inform(message); paint(); }
}

static void finish(void)
{
    if(!background){dirty=1;login_phase=QQ_LOGIN_NONE;login_refresh=0;qr_width=qr_height=0;}
    busy = background = interactive_wait = 0;
}

static void refresh_history(int automatic)
{
    unsigned previous_bottom = max_offset();
    start("正在读取近期消息…", automatic);
    interactive_wait = self.id[0]!=0;
    enum qq_result result = automatic?qq_history_cached(peer_group,peer.id,&history):qq_history(&config, peer_group, peer.id, self.id, &history);
    finish();
    if(!peer_open){history.count=0;dirty=1;return;}
    if (result) {
        if (!automatic || result != QQ_CANCELLED) inform(error_text(result));
        return;
    }
    unsigned bottom = max_offset();
    if (offset >= previous_bottom || offset > bottom) offset = bottom;
    shown_revision=qq_history_revision();dirty=1;
    inform("自动刷新  ·  I 输入  ·  Enter 发送");
}

static void get_contacts(void)
{
    if (!config_ok) return;
    if(group==2){list_loaded[2]=1;rebuild_rows(1);inform("");return;}
    unsigned was_loaded=list_loaded[group];
    list_loading[group]=1;list_error[group]=0;rebuild_rows(!was_loaded);
    start("正在载入联系人…", 0);
    interactive_wait = self.id[0]!=0;
    qq_person account;
    enum qq_result result = qq_identity(&config, &account);
    if (!result) {
        if (strcmp(self.id, account.id)) {
            memset(people, 0, sizeof people);
            memset(list_loaded, 0, sizeof list_loaded);
            memset(list_error,0,sizeof list_error);
            memset(query,0,sizeof query);memset(collapsed,0,sizeof collapsed);
            peer_open = 0;
            list_focus = 1;
            selected = first = offset = history.count = 0;
            h1net_secure_clear(draft, sizeof draft);
        }
        self = account;
        if(!list_loaded[2]){qq_recent_restore(&people[2],recent_kind);list_loaded[2]=1;}
        result = qq_contacts(&config, group, &people[group]);
    }
    list_loading[group]=0;list_error[group]=result!=QQ_OK;
    finish();
    if (result) { inform(error_text(result)); return; }
    list_loaded[group] = 1;
    rebuild_rows(!was_loaded);
    inform(people[group].truncated ? "列表达到容量上限  ·  F 搜索已载入项目" : "F 搜索  ·  Enter 展开分组或打开聊天");
}

static void select_group(unsigned next)
{
    list_focus = 1;
    if (group != next) { group = next; first = selected = 0; }
    if (!list_loaded[group]) get_contacts();else rebuild_rows(1);
    dirty = 1;
}

static void remember_chat(const qq_person *person,unsigned troop)
{
    qq_people *recent=&people[2];unsigned at=0;while(at<recent->count&&(recent_kind[at]!=troop||strcmp(recent->items[at].id,person->id)))++at;
    if(at==recent->count&&recent->count<16)++recent->count;if(at>=16)at=15;
    for(unsigned j=at;j>0;--j){recent->items[j]=recent->items[j-1];recent_kind[j]=recent_kind[j-1];}
    recent->items[0]=*person;recent->items[0].category=0;recent_kind[0]=(uint8_t)troop;
    recent->category_count=1;recent->categories[0].id=0;memcpy(recent->categories[0].name,"最近聊天",13);list_loaded[2]=1;
    (void)qq_recent_save(person,troop);
}
static void open_chat(unsigned i)
{
    if(i>=people[group].count)return;const qq_person *target=&people[group].items[i];unsigned troop=group==2?recent_kind[i]:group;
    if(draft[0]&&(troop!=peer_group||strcmp(peer.id,target->id))){inform("草稿尚未发送");return;}
    int changed=!peer_open||troop!=peer_group||strcmp(peer.id,target->id);if(changed)offset=history.count=0;
    peer=*target;peer_group=troop;peer_open=1;list_focus=0;remember_chat(&peer,troop);if(group==2)rebuild_rows(1);
    if(changed){start("",1);(void)qq_history_cached(peer_group,peer.id,&history);finish();if(!peer_open){history.count=0;return;}offset=max_offset();shown_revision=qq_history_revision();}
    refresh_history(0);
}

static void pick(unsigned row)
{
    if(row>=row_count)return;selection_visible=1;selected=row;
    if(rows[row]<0){unsigned id=(unsigned)(-rows[row]-1);if(query[group][0]){inform("搜索结果已展开，清除搜索后可折叠");return;}collapsed[group][id]^=1;rebuild_rows(0);list_focus=1;}
    else open_chat((unsigned)rows[row]);
}

static void search(void)
{
    char edited[65];memcpy(edited,query[group],sizeof edited);uint32_t now=qq_time();h1_timer_stop();close_gui();
    int accepted=qq_edit_search(edited,sizeof edited);if(!open_gui())h1ns_panic(2801);h1_timer_start();clock_base=now;
    if(accepted){memcpy(query[group],edited,sizeof edited);rebuild_rows(1);selection_visible=query[group][0]!=0;}h1net_secure_clear(edited,sizeof edited);list_focus=1;
    inform(query[group][0]?"搜索结果  ·  F 修改  ·  点 × 清除":"F 搜索备注、昵称或号码");
}

static void edit(void)
{
    if (!peer_open) return;
    list_focus = 0;
    char edited[QQ_TEXT_MAX];
    memcpy(edited, draft, sizeof edited);
    uint32_t now = qq_time();
    h1_timer_stop();
    close_gui();
    int accepted = qq_edit_text(edited, sizeof edited);
    if (!open_gui()) h1ns_panic(2801);
    h1_timer_start();
    clock_base = now;
    if (accepted) memcpy(draft, edited, sizeof draft);
    h1net_secure_clear(edited, sizeof edited);
    inform(draft[0] ? "草稿待发送  ·  Enter 发送" : "I 输入消息");
}

static void send(void)
{
    if (!draft[0]) { edit(); return; }
    start("正在发送…", 0);
    enum qq_result result = qq_send(&config, peer_group, peer.id, draft);
    finish();
    if (result) {
        inform(result == QQ_AUTH || result == QQ_REJECTED || result == QQ_OFFLINE ? error_text(result) :
               "未确认送达，草稿保留  ·  请先刷新核对");
        return;
    }
    h1net_secure_clear(draft, sizeof draft);
    inform("发送成功  ·  已收到 QQ 回执");
}

static void move_selection(int delta)
{
    selection_visible=1;unsigned count = row_count;list_pixel=0;
    if (!count) return;
    int next = (int)selected + delta;
    selected = next < 0 ? 0 : (unsigned)next >= count ? count - 1 : (unsigned)next;
    if (selected < first) first = selected;
    if (selected >= first + VISIBLE) first = selected - VISIBLE + 1;
    dirty = 1;
}

static void act(int key)
{
    if(key!=MENU_TOUCH&&menu_open){menu_open=0;dirty=1;}
    if (key >= PICK_ROW) { pick((unsigned)(key - PICK_ROW)); return; }
    switch (key) {
    case EXIT_TOUCH: if(draft[0])inform("草稿尚未发送");else closing=1;break;
    case H1_KEY_ESCAPE:
    case H1_KEY_BACK:
        if (peer_open && !draft[0]) { peer_open = 0;selection_visible=0; list_focus = 1; history.count = 0; inform("选择联系人"); }
        else if (draft[0]) inform("请先发送草稿，或按 Delete 清空草稿");
        else closing = 1;
        break;
    case H1_KEY_Q:
    case SELECT_FRIENDS: select_group(0); break;
    case H1_KEY_W:
    case SELECT_GROUPS: select_group(1); break;
    case H1_KEY_E:
    case SELECT_RECENT: select_group(2); break;
    case MENU_TOUCH: menu_open=!menu_open;dirty=1;break;
    case SETTINGS_TOUCH: settings_open=1;menu_open=0;dirty=1;break;
    case SETTINGS_BACK: settings_open=0;dirty=1;break;
    case CLEAR_HISTORY_TOUCH: if(self.id[0])settings_open=2;dirty=1;break;
    case CANCEL_CLEAR_HISTORY: settings_open=1;dirty=1;break;
    case CONFIRM_CLEAR_HISTORY:
        if(qq_clear_local_history()){memset(&people[2],0,sizeof people[2]);memset(recent_kind,0,sizeof recent_kind);list_loaded[2]=1;history.count=offset=0;shown_revision=qq_history_revision();if(group==2)rebuild_rows(1);settings_open=0;inform("历史会话已清除");}
        else inform("清除失败，请重试");dirty=1;break;
    case LIST_SCROLL_UP: scroll_list(-ROW_H);break;
    case LIST_SCROLL_DOWN: scroll_list(ROW_H);break;
    case LIST_SCROLL_PAGE_UP: scroll_list(-VISIBLE*ROW_H);break;
    case LIST_SCROLL_PAGE_DOWN: scroll_list(VISIBLE*ROW_H);break;
    case H1_KEY_R:
    case REFRESH_TOUCH:
        if (!config_ok || !self.id[0]) { load_config(); qq_net_reset(); }
        if (config_ok && peer_open && !list_focus) refresh_history(0);
        else if (config_ok) get_contacts();
        break;
    case H1_KEY_LEFT: list_focus = 1; dirty = 1; break;
    case H1_KEY_RIGHT: if (peer_open) { list_focus = 0; dirty = 1; } break;
    case H1_KEY_UP: if (list_focus) move_selection(-1); else scroll(-45); break;
    case H1_KEY_DOWN: if (list_focus) move_selection(1); else scroll(45); break;
    case H1_KEY_PAGE_UP: if (list_focus) move_selection(-VISIBLE); else scroll(-HISTORY_VIEW_H); break;
    case H1_KEY_PAGE_DOWN: if (list_focus) move_selection(VISIBLE); else scroll(HISTORY_VIEW_H); break;
    case H1_KEY_Z: list_focus = 1; move_selection(-VISIBLE); break;
    case H1_KEY_X: list_focus = 1; move_selection(VISIBLE); break;
    case H1_KEY_I:
    case H1_KEY_SPACE: edit(); break;
    case H1_KEY_ENTER:
    case H1_KEY_CONFIRM: if (list_focus) pick(selected); else send(); break;
    case H1_KEY_F:
    case SEARCH_TOUCH: search();break;
    case CLEAR_SEARCH: query[group][0]=0;rebuild_rows(1);list_focus=1;inform("已显示完整分组列表");break;
    case SEND_TOUCH: if (peer_open) { list_focus = 0; send(); } break;
    case H1_KEY_DELETE: h1net_secure_clear(draft, sizeof draft); inform("草稿已清空"); break;
    default: break;
    }
}

int h1_app_main(void)
{
    if (!fw_matches() || !open_gui()) return 1;
    h1_timer_start();
    h1ns_io_init();
    if (!setjmp(panic_return)) {
        if(!qq_paths_prepare()){inform("无法准备 QQ 数据目录，按返回退出");paint();while(!closing){qq_idle(NULL);if(pending==H1_KEY_ESCAPE||pending==H1_KEY_BACK||pending==EXIT_TOUCH)closing=1;pending=0;}h1ns_panic(2802);}
        load_config();
        /* One-shot development handoff: debugger releases USB while this BDA
         * is already in the foreground. Ordinary launches have no delay. */
        h1_file *handoff=h1_fopen(QQ_HANDOFF_PATH,"rb");
        if(handoff){
            h1_fclose(handoff);h1_remove(QQ_HANDOFF_PATH);qq_usb_handoff=1;
            inform("正在连接…");paint();uint32_t begin=qq_time();
            while(qq_time()-begin<12000&&!qq_cancel){collect();fw_delay(1);}
            qq_usb_handoff=0;
        }
        has_usb = h1net_transport_open_attached() == 0;
        if (!has_usb) inform("USB 接管失败，请拔线后重新启动");
        paint();
        while (!closing) {
            qq_idle(NULL);
            if (pending) { int key = pending; pending = 0; act(key); }
            if (closing) break;
            int connected = has_usb && h1net_transport_connected();
            if (connected != last_connected) {
                last_connected = connected;
                if (connected && config_ok) {
                    get_contacts();
                    if (peer_open) refresh_history(1);
                } else if (config_ok) inform("等待 ESP32 USB 连接");
            }
            if(connected&&qq_tick_due()){
                start("",1);enum qq_result result=qq_tick();finish();
                if(result&&result!=QQ_CANCELLED){inform(error_text(result));service_error=1;}
                else if(!result&&(service_error||!strcmp(notice,"正在注册在线状态…"))){inform("在线  ·  F 搜索  ·  Enter 打开");service_error=0;}
            }
            if(peer_open&&shown_revision!=qq_history_revision())refresh_history(1);
            if(!pending&&connected&&qq_avatar_tick_due()){start("",1);qq_avatar_tick();finish();}
            if(shown_avatar_revision!=qq_avatar_revision()){shown_avatar_revision=qq_avatar_revision();dirty=1;}
            if(!history_warned&&qq_local_history_failed()){history_warned=1;inform("本地聊天记录读写失败");}
            if(notice_until&&(int32_t)(qq_time()-notice_until)>=0){notice_until=0;dirty=1;}
            if (dirty) paint();
        }
    }
    qq_native_save_report();qq_native_shutdown();
    if (has_usb) h1net_transport_close();
    h1net_secure_clear(&config, sizeof config);
    h1net_secure_clear(draft, sizeof draft);
    h1net_secure_clear(&history, sizeof history);
    h1net_secure_clear(people, sizeof people);
    h1net_secure_clear(query,sizeof query);
    h1net_secure_clear(recent_kind,sizeof recent_kind);
    h1net_secure_clear(&self, sizeof self);
    h1net_secure_clear(&peer, sizeof peer);
    h1net_secure_clear(qr_pixels,sizeof qr_pixels);
    h1ns_io_release();
    h1ns_heap_release();
    h1_timer_stop();
    close_gui();
    return panic_code;
}
