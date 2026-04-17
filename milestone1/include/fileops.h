#ifndef FILEOPS_H
#define FILEOPS_H

// file operation functions
void list_files(const char *role_dir, char *response);
void read_file_content(const char *role_dir, const char *filename, char *response);
void copy_file_op(const char *role_dir, const char *source, const char *dest, char *response);
void write_file_op(const char *role_dir, const char *filename, const char *content, char *response);
void delete_file_op(const char *role_dir, const char *filename, char *response);

// permission checker
int check_permission(const char *role, const char *command);
char* get_role_directory(const char *role);

#endif
