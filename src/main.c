//  Created by huke on 10/3/17.
//  Copyright (c) 2017 com.cocoahuke. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <regex.h>

#define INSIDE_BUILD_PATH "/BUILD/obj/RELEASE_X86_64"

typedef enum{
    return_failed = -1,
    return_success
} tmp_return_t;

#define ARRAY_MAX 128

typedef struct arr_entry{
    void *key;
    void *value;
    struct arr_entry *next;
}arr_entry_t;

typedef struct arr{
    arr_entry_t *entry_list;
    uint32_t count;
}arr_t;

typedef struct{
    void *data;
    size_t len;
}heap_t;

heap_t *heap_new(){
    heap_t *new = malloc(sizeof(heap_t));
    if(!new) return NULL;
    bzero(new, sizeof(heap_t));
    return new;
}

heap_t *heap_newWithSize(size_t size){
    heap_t *new = heap_new();
    new->data = malloc(size);
    bzero(new->data, size);
    new->len = size;
    return new;
}

void heap_free(heap_t *heap){
    if(heap){
        if(heap->data){
            free(heap->data);
        }
        heap->data = NULL;
        heap->len = 0;
        *(intptr_t*)heap = (intptr_t)0xdeedbeef;
        free(heap);
    }
}

heap_t *heap_renewSize(heap_t *heap, size_t new_len){
    if(!heap)
        return NULL;
    if(!heap->data)
        return NULL;
    if(new_len <= heap->len)
        return NULL;
    
    char *tmp_ptr = realloc(heap->data, new_len);
    if(!tmp_ptr)
        return NULL;
    bzero(tmp_ptr + heap->len, new_len - heap->len);
    heap->data = tmp_ptr;
    heap->len = new_len;
    
    return heap;
}

heap_t *string_format_core(const char *fmt, va_list args){
    if(!fmt)
        return NULL;
    
    char *str = NULL;
    vasprintf(&str, (const char*)fmt, args);
    if(!str)
        return NULL;
    
    heap_t *rt_data = heap_new();
    rt_data->data = str;
    rt_data->len = strlen(str);
    return rt_data;
}

heap_t *string_format(const char *fmt,...){
    heap_t *rt_data = NULL;
    
    va_list args;
    va_start (args, fmt);
    rt_data = string_format_core(fmt, args);
    va_end (args);
    
    return rt_data;
}

heap_t *string_appending_format(heap_t *orig_heap, const char *fmt, ...){
    if(!orig_heap)
        return NULL;
    
    heap_t *append_str = NULL;
    
    va_list args;
    va_start (args, fmt);
    append_str = string_format_core(fmt, args);
    va_end (args);
    
    if(!append_str)
        return NULL;
    
    uint32_t old_len = (uint32_t)orig_heap->len;
    orig_heap = heap_renewSize(orig_heap, orig_heap->len + append_str->len + 1);
    if(!orig_heap){
        heap_free(append_str);
        return NULL;
    }
    
    memcpy(orig_heap->data + old_len, append_str->data, append_str->len);
    orig_heap->len --;
    ((char*)orig_heap->data)[orig_heap->len] = '\0';
    
    heap_free(append_str);
    return orig_heap;
}

char *string_remove_Unecblank(char *str, size_t str_len){
    for(size_t i = 0; i<str_len; i++){
        char c = *(str + i);
        if(c == '\0'){
            memcpy(str + i, (str + i) + 1, str_len - i);
            i--;
            str_len--;
        }
    }
    return str;
}

char *string_remove_UnecSlash(char *str){
    uint8_t bool_hasSlash = 0;
    size_t str_len = strlen(str);
    for(size_t i = 0; i<str_len; i++){
        char c = *(str + i);
        if(c == '/'){
            if(bool_hasSlash){
                *(str + i) = '\0';
            }
            else{
                bool_hasSlash = 1;
            }
        }
        else
            bool_hasSlash = 0;
    }
    str = string_remove_Unecblank(str, str_len);
    return str;
}

char *string_get_basename(char *str)
{
    char *base = strrchr(str, '/');
    return base ? base+1 : str;
}

heap_t *shell_cmd_c(char* cmd, ...){
    
    heap_t *return_data = NULL;
    
    va_list args;
    va_start (args, cmd);
    heap_t *cmd_c = string_format_core(cmd, args);
    va_end (args);
    
    if(!cmd_c)
        return NULL;
    
    do{
        FILE* in_pipe = popen(cmd_c->data, "r");
        if (!in_pipe)
            break;
        
        void *return_buf = NULL;
        uint32_t tmp_buf_len = 128;
        char tmp_buf[tmp_buf_len];
        size_t total_read = 0;
        while(!feof(in_pipe)) {
            size_t size_read = fread(tmp_buf, 1, tmp_buf_len, in_pipe);
            if(size_read){
                if(return_buf){
                    return_buf = realloc(return_buf, total_read + size_read + 1);
                    bzero(return_buf+total_read + size_read, 1);
                }
                else{
                    return_buf = malloc(size_read + 1);
                    bzero(return_buf+size_read, 1);
                }
                
                memcpy((char*)return_buf+total_read, tmp_buf, size_read);
                bzero(tmp_buf, tmp_buf_len);
                total_read += size_read;
            }
        }
        pclose(in_pipe);
        
        if(return_buf){
            ((char*)return_buf)[total_read] = '\0';
            heap_t *rt_data = heap_new();
            rt_data->data = return_buf;
            rt_data->len = total_read;
            return_data = rt_data;
        }
    }while(0);
    
    heap_free(cmd_c);
    
    return return_data;
}

arr_entry_t *arr_entry_alloc(){
    return malloc(sizeof(arr_entry_t));
}

void arr_entry_free(arr_entry_t *arr_entry){
    free(arr_entry);
}

arr_t *arr_alloc(){
    
    arr_t *new_arr = malloc(sizeof(arr_t));
    if(!new_arr)
        return NULL;
    
    bzero(new_arr, sizeof(arr_t));
    
    return new_arr;
}

void arr_free(arr_t *arr){
    if(!arr)
        return;
    
    arr_entry_t *entry_it = arr->entry_list;
    for(uint32_t i=0; entry_it && i<ARRAY_MAX; i++){
        arr_entry_t *tmp = entry_it->next;
        free(entry_it);
        entry_it = tmp;
    }
    
    free(arr);
}

arr_entry_t *arr_getByIndex(arr_t *arr, uint32_t index){
    if(!arr)
        return NULL;
    
    arr_entry_t *entry_it = arr->entry_list;
    for(uint32_t i=0; entry_it && i<ARRAY_MAX; i++){
        if(i == index)
            return entry_it;
        entry_it = entry_it->next;
    }
    return NULL;
}

tmp_return_t arr_add(arr_t *arr, void *key, void *value){
    
    if(!arr)
        return return_failed;
    
    arr_entry_t *new_entry = arr_entry_alloc();
    if(!new_entry)
        return return_failed;
    
    bzero(new_entry, sizeof(arr_entry_t));
    new_entry->key = key;
    new_entry->value = value;
    
    arr_entry_t *entry_it = arr->entry_list;
    if(!entry_it){
        arr->entry_list = new_entry;
        arr->count ++;
        return return_success;
    }
    
    for(uint32_t i=0; entry_it && i<ARRAY_MAX; i++){
        if(entry_it->key == key)
            break;
        if(!entry_it->next){
            entry_it->next = new_entry;
            arr->count ++;
            return return_success;
        }
        entry_it = entry_it->next;
    }
    
    arr_entry_free(new_entry);
    return return_failed;
}

bool file_check_fileOrDic_exist(char *path){
    if(!access(path, F_OK))
        return true;
    else
        return false;
}

size_t file_get_size(const char *path){
    struct stat buf;
    
    if ( stat(path,&buf) < 0 )
    {
        return 0;
    }
    return buf.st_size;
}

heap_t *file_read(const char *file_path){
    void *buf = NULL;
    
    size_t file_size = file_get_size(file_path);
    if(!file_size)
        return NULL;
    
    buf = malloc(file_size + 1);
    if(!buf)
        return  NULL;
    
    FILE *fp = fopen(file_path, "r");
    if(!fp){
        free(buf);
        return NULL;
    }
    
    if(fread(buf, 1, file_size, fp)!=file_size){
        free(buf);
        return NULL;
    }
    
    fclose(fp);
    
    if(buf){
        heap_t *rt_data = heap_new();
        rt_data->data = buf;
        rt_data->len = file_size;
        ((char*)rt_data->data)[rt_data->len] = '\0';
        return rt_data;
    }
    
    return NULL;;
}

tmp_return_t file_write(const char *file_path, uint32_t startloc, void *buf, size_t len){
    
    const char *fopen_flag = "rb+";
    
    if(access(file_path, F_OK))
        fopen_flag = "w";
    
    FILE *fp = fopen(file_path, fopen_flag);
    if(!fp) {
        return -1;
    }
    if(fseek(fp, startloc, SEEK_SET)<0){
        fclose(fp);
        return -2;
    }
    if(fwrite(buf, 1, len, fp)!=len){
        fclose(fp);
        return -3;
    }
    fclose(fp);
    return return_success;
}

tmp_return_t file_copy_file(const char *src_path, const char *des_path){
    
    FILE *src_fp,*des_fp;
    
    if(!(src_fp = fopen(src_path,"r")))
    {
        return -1;
    }
    
    if(file_check_fileOrDic_exist((char*)des_path)){
        fclose(src_fp);
        return -2;
    }
    if(!(des_fp = fopen(des_path,"w")))
    {fclose(src_fp);
        return -3;
    }
    
    char s = fgetc(src_fp);
    while(!feof(src_fp)){
        fputc(s,des_fp);
        s = fgetc(src_fp);
    }
    
    fclose(src_fp);
    fclose(des_fp);
    
    return return_success;
}

tmp_return_t regex_grouping(char *source_text, const char *regex_pattern, int group_count, ...){
    
    tmp_return_t xr = 1;
    arr_t **return_data_groups[group_count];
    regex_t reg;
    int eflags = 0;
    size_t offset = 0;
    size_t length = strlen(source_text);
    size_t maxGroups = group_count;
    regmatch_t all_matches[group_count];
    
    va_list args;
    va_start (args, group_count);
    for(int i = 0; i< group_count;i ++){
        return_data_groups[i] = va_arg(args, arr_t**);
    }
    va_end (args);
    
    if(regcomp(&reg, regex_pattern, REG_EXTENDED| REG_ENHANCED| REG_UNGREEDY| REG_NEWLINE)){
        xr = 1;
        goto End;
    }
    
    while (regexec(&reg, source_text + offset, maxGroups, all_matches, eflags) == 0) {
        eflags = REG_NOTBOL;
        
        for (int g = 0; g < maxGroups; g++)
        {
            arr_t **arr_group = return_data_groups[g];
            if(!arr_group)
                continue;
            
            if (all_matches[g].rm_so == (size_t)-1){
                xr = 1;
                break;
            }
            
            uint64_t match_len = (offset + all_matches[g].rm_eo) - (offset + all_matches[g].rm_so);
            
            if(!*arr_group){
                xr = 0;
                *arr_group = arr_alloc();
            }
            arr_add(*arr_group, source_text + (offset + all_matches[g].rm_so), (void*)match_len);
        }
        
        offset += all_matches[0].rm_eo;
        
        if (all_matches[0].rm_so == all_matches[0].rm_eo) {
            offset += 1;
        }
        
        if (offset > length) {
            break;
        }
    }
    
End:
    regfree(&reg);
    return xr;
}

heap_t *regex_findAndReplace(char *source_text, const char *regex_pattern, char *replace_text, ...){
    heap_t *return_data = NULL;
    regex_t reg;
    int eflags = 0;
    size_t offset = 0;
    size_t length = strlen(source_text);
    size_t maxGroups = 1;
    regmatch_t all_matches[maxGroups];
    
    if(!source_text)
        return NULL;
    
    return_data = heap_newWithSize(strlen(source_text)+1);
    return_data->len -= 1;
    memcpy(return_data->data, source_text, strlen(source_text));
    
    va_list args;
    va_start (args, replace_text);
    heap_t *hvreplace_text = string_format_core(replace_text, args);
    va_end (args);
    
    if(!hvreplace_text)
        return NULL;
    
    if(regcomp(&reg, regex_pattern, REG_EXTENDED| REG_ENHANCED| REG_UNGREEDY| REG_NEWLINE))
        goto End;
    
    while (regexec(&reg, return_data->data + offset, maxGroups, all_matches, eflags) == 0) {
        eflags = REG_NOTBOL;
        
        for (int g = 0; g < maxGroups; g++)
        {
            if (all_matches[g].rm_so == (size_t)-1)
                break;
            
            uint64_t match_end = offset + all_matches[g].rm_eo;
            uint64_t match_start = offset + all_matches[g].rm_so;
            uint64_t match_len = (offset + all_matches[g].rm_eo) - (offset + all_matches[g].rm_so);
            
            if(hvreplace_text->len == match_len){
                memcpy(return_data->data + match_start, hvreplace_text->data, hvreplace_text->len);
            }else if(hvreplace_text->len > match_len){
                size_t increase_bytes = hvreplace_text->len - match_len;
                size_t old_len = return_data->len;
                return_data->len = old_len + increase_bytes;
                return_data->data = realloc(return_data->data, return_data->len + 1);
                ((char*)return_data->data)[return_data->len] = '\0';
                memmove(return_data->data + match_start + hvreplace_text->len, return_data->data + match_start + match_len, old_len - match_end);
                memcpy(return_data->data + match_start, hvreplace_text->data, hvreplace_text->len);
                length += increase_bytes;
                offset += increase_bytes;
            }else if(hvreplace_text->len < match_len){
                size_t decrease_bytes = match_len - hvreplace_text->len;
                memmove(return_data->data + match_start + hvreplace_text->len, return_data->data + match_start + match_len, return_data->len - match_end);
                memcpy(return_data->data + match_start, hvreplace_text->data, hvreplace_text->len);
                return_data->len = return_data->len - decrease_bytes;
                return_data->data = realloc(return_data->data, return_data->len + 1);
                ((char*)return_data->data)[return_data->len] = '\0';
                length -= decrease_bytes;
                offset -= decrease_bytes;
            }
        }
        
        offset += all_matches[0].rm_eo;
        
        if (all_matches[0].rm_so == all_matches[0].rm_eo) {
            offset += 1;
        }
        
        if (offset > length) {
            break;
        }
    }
    
End:
    heap_free(hvreplace_text);
    regfree(&reg);
    return return_data;
}

char *input_xnusource_path = NULL;
char *input_xnusource_BUILD_path = NULL;
char *input_export_path = NULL;
char *input_export_name = NULL;

void heap_cleanEOL(heap_t *heap){
    if(heap && heap->data){
        if(!strncmp(heap->data + (heap->len-1), "\n", 1))
            *(char*)(heap->data + (heap->len-1)) = '\0';
    }
}

bool is_string_include_char(const char *str, size_t str_len, char c){;
    for(size_t i = 0; i<str_len; i++){
        char each_c = *(str + i);
        if(each_c == c){
            return true;
        }
    }
    return false;
}

#define PATH_CONVERT(A, B, C) if(!strncmp(include_path->key, A, strlen(A))){ \
bzero(tmp_pattern, sizeof(tmp_pattern)); \
memcpy(tmp_pattern, B, strlen(B)); \
memcpy(tmp_pattern + strlen(B), C, strlen(C)); \
memcpy(tmp_pattern + strlen(B) + strlen(C), include_path->key + strlen(A), (size_t)(include_path->value) - strlen(A)); \
return tmp_pattern; \
} \

#define PATH_CONVERT_2(A, B, C) if(!strncmp(path_under_xnuSourceCode, C,\
strlen(C)) && !strncmp(include_path, A, strlen(A))){\
bzero(tmp_pattern, sizeof(tmp_pattern));\
memcpy(tmp_pattern, B, strlen(B));\
memcpy(tmp_pattern + strlen(B), include_path + strlen(A), strlen(include_path) - strlen(A));\
return tmp_pattern;}

#define PATH_CONVERT_3(A) if(!strncmp(include_path->key, A, strlen(A))){ \
return "";}

/*Files from dynamic generation:
 gssd_mach.h
 */
char tmp_pattern[128];
const char *replace_pattern(const char *header_path, arr_entry_t *include_path){
    
    const char *path_under_xnuSourceCode = header_path + strlen(input_export_path);
    
    PATH_CONVERT("security/", input_export_name, "/security/");
    PATH_CONVERT("sys/", input_export_name, "/bsd/sys/");
    PATH_CONVERT("vm/", input_export_name, "/osfmk/vm/");
    PATH_CONVERT("mach/", input_export_name, "/osfmk/mach/");
    PATH_CONVERT("uuid/", input_export_name, "/bsd/uuid/");
    PATH_CONVERT("miscfs/", input_export_name, "/bsd/miscfs/");
    PATH_CONVERT("inet/", input_export_name, "/bsd/inet/");
    PATH_CONVERT("netkey/", input_export_name, "/bsd/netkey/");
    PATH_CONVERT("netinet/", input_export_name, "/bsd/netinet/");
    PATH_CONVERT("netinet6/", input_export_name, "/bsd/netinet6/");
    PATH_CONVERT("crypto/", input_export_name, "/bsd/crypto/");
    PATH_CONVERT("net/", input_export_name, "/bsd/net/");
    PATH_CONVERT("nfs/", input_export_name, "/bsd/nfs/");
    PATH_CONVERT("vfs/", input_export_name, "/bsd/vfs/");
    PATH_CONVERT("bsm/", input_export_name, "/bsd/bsm/");
    PATH_CONVERT("System/sys/", input_export_name, "/bsd/sys/");
    PATH_CONVERT("System/i386/", input_export_name, "/osfmk/i386/");
    PATH_CONVERT("System/libkern/", input_export_name, "/libkern/libkern/");
    PATH_CONVERT("stdio.h", input_export_name, "/bsd/sys/stdio.h");
    PATH_CONVERT("malloc.h", input_export_name, "/bsd/sys/malloc.h");
    PATH_CONVERT("stdio.h", input_export_name, "/bsd/sys/stdio.h");
    PATH_CONVERT("unistd.h", input_export_name, "/bsd/sys/unistd.h");
    PATH_CONVERT("errno.h", input_export_name, "/bsd/sys/errno.h");
    PATH_CONVERT("stdlib.h", input_export_name, "/osfmk/libsa/stdlib.h");
    PATH_CONVERT("string.h", input_export_name, "/osfmk/libsa/string.h");
    
    PATH_CONVERT("atm/", input_export_name, "/osfmk/atm/");
    PATH_CONVERT("ipc/", input_export_name, "/osfmk/ipc/");
    PATH_CONVERT("bank/", input_export_name, "/osfmk/bank/");
    PATH_CONVERT("mach_debug/", input_export_name, "/osfmk/mach_debug/");
    PATH_CONVERT("kern/", input_export_name, "/osfmk/kern/")
    PATH_CONVERT("device/", input_export_name, "/osfmk/device/")
    PATH_CONVERT("console/", input_export_name, "/osfmk/console/")
    PATH_CONVERT("pexpert/", input_export_name, "/pexpert/pexpert/")
    PATH_CONVERT("voucher/", input_export_name, "/osfmk/voucher/")
    PATH_CONVERT("kdp/", input_export_name, "/osfmk/kdp/")
    PATH_CONVERT("libsa/", input_export_name, "/osfmk/libsa/")
    PATH_CONVERT("kperf/", input_export_name, "/osfmk/kperf/")
    PATH_CONVERT("os/", input_export_name, "/libkern/os/")
    PATH_CONVERT("UserNotification/", input_export_name, "/osfmk/UserNotification/")
    PATH_CONVERT("profiling/", input_export_name, "/osfmk/profiling/")
    PATH_CONVERT("prng/", input_export_name, "/osfmk/prng/")
    
    PATH_CONVERT("IOKit/", input_export_name, "/iokit/IOKit/")
    
    
    //EXTERNAL_HEADERS (Move to root dir of SDK)
    PATH_CONVERT("mach-o/", input_export_name, "/mach-o/");
    PATH_CONVERT("corecrypto/", input_export_name, "/corecrypto/");
    PATH_CONVERT("Availability.h", input_export_name, "/Availability.h");
    PATH_CONVERT("stdint.h", input_export_name, "/stdint.h");
    PATH_CONVERT("stdbool.h", input_export_name, "/stdbool.h");
    PATH_CONVERT("stdarg.h", input_export_name, "/stdarg.h");
    PATH_CONVERT("stdatomic.h", input_export_name, "/stdatomic.h");
    PATH_CONVERT("stddef.h", input_export_name, "/stddef.h");
    PATH_CONVERT("AvailabilityInternal.h", input_export_name, "/AvailabilityInternal.h");
    PATH_CONVERT("architecture/", input_export_name, "/architecture/");
    //---
    
    PATH_CONVERT("libkern/libkern.h", input_export_name, "/bsd/libkern/libkern.h");
    PATH_CONVERT("libkern/", input_export_name, "/libkern/libkern/");
    PATH_CONVERT("firehose/", input_export_name, "/libkern/firehose/");
    
    //i386/ -> osfmk/i386/ ? bsd/i386/
    //machine/ -> osfmk/machine/ ? bsd/machine/
    
    if(!strncmp(include_path->key, "machine/", strlen("machine/")) || !strncmp(include_path->key, "i386/", strlen("i386/"))){
        heap_t *hvppath1 = string_format("%s/bsd/%.*s", input_xnusource_path, include_path->value, include_path->key);
        heap_t *hvppath2 = string_format("%s/osfmk/%.*s", input_xnusource_path, include_path->value, include_path->key);
        if(!hvppath1 || !hvppath2)
            exit(1);
        char *str1 = "/bsd/";
        bzero(tmp_pattern, sizeof(tmp_pattern));
        if(file_check_fileOrDic_exist(hvppath1->data)){
            str1 = "/bsd/";
        }
        else if(file_check_fileOrDic_exist(hvppath2->data)){
            str1 = "/osfmk/";
        }
        
        heap_free(hvppath1);
        heap_free(hvppath2);
        
        memcpy(tmp_pattern, input_export_name, strlen(input_export_name));
        memcpy(tmp_pattern + strlen(input_export_name), str1, strlen(str1));
        memcpy(tmp_pattern + strlen(input_export_name) + strlen(str1), include_path->key, (size_t)include_path->value);
        return tmp_pattern;
    }
    
    if(!strncmp(path_under_xnuSourceCode, "/bsd/sys/", strlen("/bsd/sys/")) && !is_string_include_char(include_path->key, (size_t)include_path->value, '/')){
        bzero(tmp_pattern, sizeof(tmp_pattern));
        memcpy(tmp_pattern, input_export_name, strlen(input_export_name));
        memcpy(tmp_pattern + strlen(input_export_name), "/bsd/sys/", strlen("/bsd/sys/"));
        memcpy(tmp_pattern + strlen(input_export_name) + strlen("/bsd/sys/"), include_path->key, (size_t)include_path->value);
        return tmp_pattern;
    }
    
    if(!strncmp(path_under_xnuSourceCode, "/osfmk/libsa/", strlen("/osfmk/libsa/")) && !is_string_include_char(include_path->key, (size_t)include_path->value, '/')){
        bzero(tmp_pattern, sizeof(tmp_pattern));
        memcpy(tmp_pattern, input_export_name, strlen(input_export_name));
        memcpy(tmp_pattern + strlen(input_export_name), "/osfmk/libsa/", strlen("/osfmk/libsa/"));
        memcpy(tmp_pattern + strlen(input_export_name) + strlen("/osfmk/libsa/"), include_path->key, (size_t)include_path->value);
        return tmp_pattern;
    }
    
    //Unnecessary (Not exist or not able to use)
    PATH_CONVERT_3("linux/");
    PATH_CONVERT_3("CoreFoundation/");
    PATH_CONVERT_3("windows.h");
    PATH_CONVERT_3("unixio.h");
    PATH_CONVERT_3("alloc.h");
    PATH_CONVERT_3("unix.h");
    PATH_CONVERT_3("AvailabilityProhibitedInternal.h");
    
    //Unnecessary files (It's include in /usr/include, so these Will not be added to generated headers)
    PATH_CONVERT_3("TargetConditionals.h");
    PATH_CONVERT_3("_types/_uint32_t.h");
    PATH_CONVERT_3("_types/_uint64_t.h");
    PATH_CONVERT_3("xpc/");
    PATH_CONVERT_3("san/");
    PATH_CONVERT_3("MacTypes.h");
    PATH_CONVERT_3("inttypes.h");
    PATH_CONVERT_3("assert.h");
    
    //Copy from pre-compiler xnu
    PATH_CONVERT("gssd/", input_export_name, "/osfmk/RELEASE/gssd/");
    PATH_CONVERT("gprof.h", input_export_name, "/osfmk/RELEASE/gprof.h");
    PATH_CONVERT("mach_assert.h", input_export_name, "/osfmk/RELEASE/mach_assert.h");
    PATH_CONVERT("mach_ldebug.h", input_export_name, "/osfmk/RELEASE/mach_ldebug.h");
    PATH_CONVERT("mach_rt.h", input_export_name, "/osfmk/RELEASE/mach_rt.h");
    PATH_CONVERT("mach_debug.h", input_export_name, "/osfmk/RELEASE/mach_debug.h");
    PATH_CONVERT("mach_ipc_debug.h", input_export_name, "/osfmk/RELEASE/mach_ipc_debug.h");
    PATH_CONVERT("mach_counters.h", input_export_name, "/osfmk/RELEASE/mach_counters.h");
    PATH_CONVERT("task_swapper.h", input_export_name, "/osfmk/RELEASE/task_swapper.h");
    PATH_CONVERT("mach_pagemap.h", input_export_name, "/osfmk/RELEASE/mach_pagemap.h");
    PATH_CONVERT("debug.h", input_export_name, "/osfmk/RELEASE/debug.h");
    PATH_CONVERT("xpr_debug.h", input_export_name, "/osfmk/RELEASE/xpr_debug.h");
    PATH_CONVERT("zone_debug.h", input_export_name, "/osfmk/RELEASE/zone_debug.h");
    
    //printf("%s: ", path_under_xnuSourceCode);
    return NULL;
}

uint32_t replace_count = 0;

void find_replace(const char *file_path){
    heap_t *hvfile = file_read(file_path);
    if(!hvfile)
        return;
    
    arr_t *arr_old_includepath = NULL;
    regex_grouping(hvfile->data, "#\\s*include\\s*[<\"]\\s*(.*)\\s*[>\"].*", 2, NULL, &arr_old_includepath);
    if(!arr_old_includepath){
        heap_free(hvfile);
        return;
    }
    
    heap_t *hvFinal_writedata = NULL;
    for(int i=0; i<arr_old_includepath->count; i++){
        arr_entry_t *entry_old_includepath = arr_getByIndex(arr_old_includepath, i);
        
        //Print string contained in #include
        printf("%d. %.*s\n", i, (int)entry_old_includepath->value, entry_old_includepath->key);
        
        //printf("%d.  ", replace_count++);
        
        const char *new_includepath = replace_pattern(file_path, entry_old_includepath);
        if(new_includepath){
            if(strlen(new_includepath) != 0){
                //We have new path now, replace old path then
                heap_t *hvRegex_oldpath = string_format("#\\s*include\\s*[<\"]\\s*%.*s\\s*[>\"].*", entry_old_includepath->value, entry_old_includepath->key);
                if(!hvRegex_oldpath){
                    printf("Mem error\n");
                    exit(1);
                }
                
                heap_t *hvRegex_oldpath_escaped = regex_findAndReplace(hvRegex_oldpath->data, "\\+", "\\+");
                heap_free(hvRegex_oldpath);
                if(!hvRegex_oldpath_escaped){
                    printf("mem error\n");
                    exit(1);
                }
                
                //printf("%s\n", hvRegex_oldpath->data);
                heap_t *hvnewfile = regex_findAndReplace(hvFinal_writedata?hvFinal_writedata->data:hvfile->data, hvRegex_oldpath_escaped->data, "#include <%s>", new_includepath);
                heap_free(hvRegex_oldpath_escaped);
                
                if(hvnewfile){
                    heap_free(hvFinal_writedata);
                    hvFinal_writedata = hvnewfile;
                }
                
                printf("  %.*s >>> %s\n", (uint32_t)entry_old_includepath->value, entry_old_includepath->key, new_includepath);
            }
            else{
                //Delete
                heap_t *hvRegex_oldpath = string_format("#\\s*include\\s*[<\"]\\s*%.*s\\s*[>\"].*", entry_old_includepath->value, entry_old_includepath->key);
                if(!hvRegex_oldpath){
                    printf("Mem error\n");
                    exit(1);
                }
                
                heap_t *hvRegex_oldpath_escaped = regex_findAndReplace(hvRegex_oldpath->data, "\\+", "\\+");
                heap_free(hvRegex_oldpath);
                if(!hvRegex_oldpath_escaped){
                    printf("mem error\n");
                    exit(1);
                }
                
                //printf("%s\n", hvRegex_oldpath->data);
                heap_t *hvnewfile = regex_findAndReplace(hvFinal_writedata?hvFinal_writedata->data:hvfile->data, hvRegex_oldpath_escaped->data, "");
                heap_free(hvRegex_oldpath_escaped);
                
                if(hvnewfile){
                    heap_free(hvFinal_writedata);
                    hvFinal_writedata = hvnewfile;
                }
                
                //printf("%s\n", hvnewfile->data);
                
                printf("  %.*s xxx\n", (uint32_t)entry_old_includepath->value, entry_old_includepath->key);
                //printf("PPP\n");
            }
        }
        else{
            //Can't find the replacement
            
            printf("  %.*s >>> ???\n", (uint32_t)entry_old_includepath->value, entry_old_includepath->key);
        }
        
    }
    arr_free(arr_old_includepath);
    
    if(hvFinal_writedata){
        remove(file_path);
        file_write(file_path, 0, hvFinal_writedata->data, hvFinal_writedata->len);
        heap_free(hvFinal_writedata);
    }
    heap_free(hvfile);
}

void copy_headers_under_folder(const char *src_dirpath, const char *des_dirpath){
    
    heap_t *hvfind_result = shell_cmd_c("cd %s/%s && find . -type file -name \"*.h\" && echo \\*\\*\\* && cd %s/%s &> /dev/null && find . -type file -name \"*.h\"", input_xnusource_path, src_dirpath, input_xnusource_BUILD_path, src_dirpath);
    if(!hvfind_result){
        printf("find command-line tool couldn't find any headers\n");
        exit(1);
    }
    
    char* vstrtok = NULL, *tmp1 = input_xnusource_path;
    char *header_path = strtok_r(hvfind_result->data, "\n", &vstrtok);
    while (header_path != NULL)
    {
        if(!strcmp(header_path, "***")){
            tmp1 = input_xnusource_BUILD_path;
            header_path = strtok_r(NULL, "\n", &vstrtok);
            continue;
            //goto Next_round;
        }
        char *header_exportdirpath = NULL;
        char *header_srcdirpath = NULL;
        char *header_filename = NULL;
        
        heap_t *hv768 = shell_cmd_c("dirname %s", header_path);
        heap_cleanEOL(hv768);
        
        if(!strncmp(hv768->data, ".", 1))
            header_exportdirpath = hv768->data + 1;
        else
            header_exportdirpath = hv768->data;
        
        heap_t *hv895 = string_format("%s%s/", src_dirpath, header_exportdirpath);
        header_srcdirpath = hv895->data;
        
        heap_t *hv834 = string_format("%s%s/", des_dirpath, header_exportdirpath);
        header_exportdirpath = hv834->data;
        
        heap_free(hv768);
        
        header_filename = string_get_basename(header_path);
        
        heap_t *hv5 = string_format("mkdir -p %s/%s", input_export_path, header_exportdirpath);
        
        FILE* in_pipe = popen(hv5->data, "r");
        if (in_pipe)
            pclose(in_pipe);

        heap_free(hv5);
        
        heap_t *hv6 = string_format("%s/%s/%s", tmp1, header_srcdirpath, header_filename);
        heap_t *hv7 = string_format("%s/%s/%s", input_export_path, header_exportdirpath, header_filename);
        
        printf("%s -> %s ", string_remove_UnecSlash(hv6->data), string_remove_UnecSlash(hv7->data));
        
        int copy_err = file_copy_file(hv6->data, hv7->data);
        printf("%s\n", copy_err?"x":"✔");
        
        find_replace(hv7->data);
        
        heap_free(hv6);
        heap_free(hv7);
        
        heap_free(hv834);
        heap_free(hv895);
    Next_round:
        header_path = strtok_r(NULL, "\n", &vstrtok);
    }
}

char machsyscall_header_declaration[] = "//\n//  machtrap.h\n//  https://github.com/cocoahuke/rootkitdev_genheaders\n//\n\n";

heap_t *build_machsyscall_header_data(){
    
    heap_t *return_data = NULL;
    heap_t *heap_syscall_sw_path = string_format("%s/osfmk/kern/syscall_sw.c", input_xnusource_path);
    if(!heap_syscall_sw_path){
        printf("mem err\n");
        return NULL;
    }
    
    heap_t *heap_syscall_sw_content = file_read(heap_syscall_sw_path->data);
    heap_free(heap_syscall_sw_path);
    if(!heap_syscall_sw_content){
        printf("mem err\n");
        return NULL;
    }
    
    arr_t *arr_machtrap_numbers = NULL;
    arr_t *arr_machtrap_names = NULL;
    regex_grouping(heap_syscall_sw_content->data, "/\\*\\s*?(.*)\\s*?\\*/.*\\\"\\s*?(.*)\\s*?\\\",", 3, NULL, &arr_machtrap_numbers, &arr_machtrap_names);
    heap_free(heap_syscall_sw_content);
    if(!arr_machtrap_numbers || !arr_machtrap_names){
        printf("regex error 3443\n");
        if(arr_machtrap_numbers)
            arr_free(arr_machtrap_numbers);
        if(arr_machtrap_names)
            arr_free(arr_machtrap_names);
        return NULL;
    }
    
    uint32_t mach_maxsyscall = 0;
    return_data = string_format("%s", machsyscall_header_declaration);
    if(!return_data){
        printf("mem error\n");
        exit(1);
    }
    
    for(int i=0; i<arr_machtrap_names->count; i++){
        mach_maxsyscall++;
        arr_entry_t *entry_name = arr_getByIndex(arr_machtrap_names, i);
        arr_entry_t *entry_number = arr_getByIndex(arr_machtrap_numbers, i);
        
        const char *tmpkeyword = "kern_invalid";
        if((strlen(tmpkeyword) == (size_t)entry_name->value && !memcmp(tmpkeyword, entry_name->key, (size_t)entry_name->value)) == false){
            
            return_data = string_appending_format(return_data, "#define MACH_%.*s %.*s\n", entry_name->value, entry_name->key, entry_number->value, entry_number->key);
            if(!return_data){
                printf("mem error\n");
                exit(1);
            }
            
            //printf("#define MACH_%.*s %.*s\n", (uint32_t)entry_name->value, entry_name->key, (uint32_t)entry_number->value, entry_number->key);
        }
    }
    
    return_data = string_appending_format(return_data, "#define MACH_MAXSYSCALL %d\n", mach_maxsyscall);
    
    if(arr_machtrap_numbers)
        arr_free(arr_machtrap_numbers);
    if(arr_machtrap_names)
        arr_free(arr_machtrap_names);
    return return_data;
}

void create_machsyscall_header(){
    heap_t *file_content = build_machsyscall_header_data();
    if(file_content){
        heap_t *file_path = string_format("%s/osfmk/mach/machtrap.h", input_export_path);
        if(!file_path){
            printf("mem error\n");
            exit(1);
        }
        file_write(file_path->data, 0, file_content->data, file_content->len);
        
        printf("%s created\n", file_path->data);
        heap_free(file_path);
        heap_free(file_content);
    }
}

/*
 rootkitdev_genheaders <path: xnu source folder> <path: output folder>
 */
int main(int argc, const char * argv[]) {
    
    if(argc != 3){
        printf("The number of arguments is wrong, please specify 2 parameters ONLY.\n");
        printf("Format as below:\n");
        printf("rootkitdev_genheaders <path: xnu source folder> <path: output folder>\n");
        exit(1);
    }
    
    input_xnusource_path = (char*)argv[1];
    
    //Remove the last character if it's slash
    if(input_xnusource_path[strlen(input_xnusource_path)-1] == '/')
        input_xnusource_path[strlen(input_xnusource_path)-1] = '\0';
    
    char tmpbuildpath[strlen(input_xnusource_path) + sizeof(INSIDE_BUILD_PATH)];
    memcpy(tmpbuildpath, input_xnusource_path, strlen(input_xnusource_path));
    memcpy(tmpbuildpath + strlen(input_xnusource_path), INSIDE_BUILD_PATH, sizeof(INSIDE_BUILD_PATH));
    input_xnusource_BUILD_path = tmpbuildpath;
    input_export_path = (char*)argv[2];
    
    //Remove the last character if it's slash
    if(input_export_path[strlen(input_export_path)-1] == '/')
        input_export_path[strlen(input_export_path)-1] = '\0';
    
    input_export_name = string_get_basename(input_export_path);
    
    if(!file_check_fileOrDic_exist(input_xnusource_path)){
        printf("input: unvalid xnu source code path\n");
        exit(1);
    }
    
    if(!file_check_fileOrDic_exist(input_xnusource_BUILD_path)){
        printf("Please start at least little bit compile work in xnu source, util you find any file under %s\n", input_xnusource_BUILD_path);
        exit(1);
    }
    
    if(file_check_fileOrDic_exist(input_export_path)){
        printf("Error: output path is occupied\n");
        exit(1);
    }
    
    mkdir(input_export_path, S_IRWXG|S_IRWXU|S_IRWXO);
    
    //If you want to test a specific file
    //find_replace("/Desktop/xnu_export/Availability.h"); exit(1);
    
    copy_headers_under_folder("/security", "/security");
    copy_headers_under_folder("/bsd", "/bsd");
    copy_headers_under_folder("/osfmk", "/osfmk");
    copy_headers_under_folder("/libkern", "/libkern");
    copy_headers_under_folder("/pexpert", "/pexpert");
    copy_headers_under_folder("/EXTERNAL_HEADERS", "/");
    copy_headers_under_folder("/iokit", "/iokit");
    create_machsyscall_header();
    
    printf("Complete\n");
    
    return 0;
}

