#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include "fileops.h"

// dumbest way: return directory path based on role
char* get_role_directory(const char *role) {
    static char dir[256];
    if (strcmp(role, "entry") == 0) {
        strcpy(dir, "files/entry");
    } else if (strcmp(role, "medium") == 0) {
        strcpy(dir, "files/medium");
    } else if (strcmp(role, "top") == 0) {
        strcpy(dir, "files/top");
    } else {
        strcpy(dir, "files/entry");  // default to entry
    }
    return dir;
}

// check if role can execute command
int check_permission(const char *role, const char *command) {
    // entry level: only ls and cat allowed
    if (strcmp(role, "entry") == 0) {
        if (strncmp(command, "ls", 2) == 0 || strncmp(command, "cat", 3) == 0) {
            return 1;  // allowed
        }
        return 0;  // denied
    }
    
    // medium level: ls, cat, cp, edit allowed (no rm/delete)
    if (strcmp(role, "medium") == 0) {
        if (strncmp(command, "ls", 2) == 0 || 
            strncmp(command, "cat", 3) == 0 ||
            strncmp(command, "cp", 2) == 0 ||
            strncmp(command, "edit", 4) == 0) {
            return 1;  // allowed
        }
        return 0;  // denied
    }
    
    // top level: everything allowed
    if (strcmp(role, "top") == 0) {
        return 1;  // all commands allowed
    }
    
    return 0;  // default deny
}

// list all files in role directory
void list_files(const char *role_dir, char *response) {
    DIR *dir = opendir(role_dir);
    if (!dir) {
        sprintf(response, "Error: Cannot open directory %s", role_dir);
        return;
    }
    
    strcpy(response, "Files:\n");
    struct dirent *entry;
    
    while ((entry = readdir(dir)) != NULL) {
        // skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        strcat(response, "  - ");
        strcat(response, entry->d_name);
        strcat(response, "\n");
    }
    closedir(dir);
}

// read file contents
void read_file_content(const char *role_dir, const char *filename, char *response) {
    // build full path
    char filepath[512];
    sprintf(filepath, "%s/%s", role_dir, filename);
    
    FILE *file = fopen(filepath, "r");
    if (!file) {
        sprintf(response, "Error: Cannot open file %s", filename);
        return;
    }
    
    // read entire file into response
    char buffer[2048];
    strcpy(response, "");
    while (fgets(buffer, sizeof(buffer), file)) {
        strcat(response, buffer);
    }
    fclose(file);
}

// copy file
void copy_file_op(const char *role_dir, const char *source, const char *dest, char *response) {
    char src_path[512], dest_path[512];
    sprintf(src_path, "%s/%s", role_dir, source);
    sprintf(dest_path, "%s/%s", role_dir, dest);
    
    // read source
    FILE *src = fopen(src_path, "r");
    if (!src) {
        sprintf(response, "Error: Cannot open source file %s", source);
        return;
    }
    
    // write destination
    FILE *dst = fopen(dest_path, "w");
    if (!dst) {
        fclose(src);
        sprintf(response, "Error: Cannot create destination file %s", dest);
        return;
    }
    
    // copy content
    char buffer[2048];
    while (fgets(buffer, sizeof(buffer), src)) {
        fputs(buffer, dst);
    }
    
    fclose(src);
    fclose(dst);
    sprintf(response, "File copied: %s -> %s", source, dest);
}

// write/edit file
void write_file_op(const char *role_dir, const char *filename, const char *content, char *response) {
    char filepath[512];
    sprintf(filepath, "%s/%s", role_dir, filename);
    
    FILE *file = fopen(filepath, "w");
    if (!file) {
        sprintf(response, "Error: Cannot open file %s for writing", filename);
        return;
    }
    
    fputs(content, file);
    fclose(file);
    sprintf(response, "File edited: %s", filename);
}

// delete file
void delete_file_op(const char *role_dir, const char *filename, char *response) {
    char filepath[512];
    sprintf(filepath, "%s/%s", role_dir, filename);
    
    if (remove(filepath) == 0) {
        sprintf(response, "File deleted: %s", filename);
    } else {
        sprintf(response, "Error: Cannot delete file %s", filename);
    }
}
