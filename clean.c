//void display_port_mirroring_config_from_db(int serial_port)
void display_port_mirroring_config_from_db(int serial_port, int show_prompt)
{
  sqlite3 *db;
  sqlite3_stmt *stmt;
  int rc = sqlite3_open(DB_PATH, &db);
  sqlite3_busy_timeout(db, 2000); 
 
  if (rc)
  {
    printf("\n cannot open database: %s\n", sqlite3_errmsg(db));
    return;
  }

  const char *sql =
      "SELECT di.InterfaceId, di.InterfaceIsMirroring, di.InterfaceName, "
      "mi.InterfaceName AS MonitorInterfaceName, "
      "di.InterfaceMirrorSetting, di.MirrorType, di.Value "
      "FROM DeviceInterfaces di "
      "LEFT JOIN DeviceInterfaces mi ON di.InterfaceToMonitorInterfaceId = mi.InterfaceId";

  rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK)
  {
    printf("\nError query: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return;
  }

  printf("\n=============================================================================================================================================================================================================+\n");
  printf("| %-3s | %-15s | %-10s | %-22s | %-22s | %-50s | %-62s |\n",
         "No", "InterfaceName", "Mirroring", "Monitor Interface ID", "MirrorSetting", "MirrorType", "Value");
  printf("|=====|=================|============|========================|========================|====================================================|================================================================|\n");

  int idx = 1;
  while (sqlite3_step(stmt) == SQLITE_ROW)
  {
    int mirroring = sqlite3_column_int(stmt, 1);
    const unsigned char *interface_name = sqlite3_column_text(stmt, 2);
    const unsigned char *monitor_name = sqlite3_column_text(stmt, 3);
    const unsigned char *setting = sqlite3_column_text(stmt, 4);
    const unsigned char *type = sqlite3_column_text(stmt, 5);
    const unsigned char *value = sqlite3_column_text(stmt, 6);

    const char *mirroring_str = mirroring ? "Active" : "Inactive";
    const char *interface_name_str = interface_name ? (const char *)interface_name : "";
    const char *monitor_name_str = monitor_name ? (const char *)monitor_name : "N/A";
    const char *setting_str = setting ? (const char *)setting : "";
    char cleaned_type[512] = "";
    if (type)
      clean_json_array_string((const char *)type, cleaned_type, sizeof(cleaned_type));
    else
      strcpy(cleaned_type, "");

    const char *value_str = value ? (const char *)value : "";

    char extracted_values[512] = "";
    if (value_str && strlen(value_str) > 0)
      extract_json_values(value_str, extracted_values, sizeof(extracted_values));
    printf("| %-3d | %-15s | %-10s | %-22s | %-22s |", idx++, interface_name_str, mirroring_str, monitor_name_str, setting_str);

    // In MirrorType và Value xuống dòng nếu dài
    int max_width_type = 50;
    int max_width_value = 62;

    // In phần đầu tiên của MirrorType
    printf(" %-*.*s |", max_width_type, max_width_type, cleaned_type);

    printf(" %-*.*s |\n", max_width_value, max_width_value, extracted_values);

    // In phần tiếp theo nếu MirrorType hoặc Value dài
    int type_len = strlen(cleaned_type);
    int value_len = strlen(extracted_values);
    int line = 1;
    while (line * max_width_type < type_len || line * max_width_value < value_len)
    {
      printf("| %-3s | %-15s | %-10s | %-22s | %-22s |", "", "", "", "", "");

      if (line * max_width_type < type_len)
        printf(" %-*.*s |", max_width_type, max_width_type, cleaned_type + line * max_width_type);
      else
        printf(" %-*s |", max_width_type, "");

      if (line * max_width_value < value_len)
        printf(" %-*.*s |\n", max_width_value, max_width_value, extracted_values + line * max_width_value);
      else
        printf(" %-*s |\n", max_width_value, "");

      line++;
    }
    printf("|-----+-----------------+------------+------------------------+------------------------+----------------------------------------------------+----------------------------------------------------------------|\n");
  }
  //printf("Press Enter to return to menu...\n");
  
  if (show_prompt)
  {
    printf("Press Enter to return to menu...");
  }

  sqlite3_finalize(stmt);
  sqlite3_close(db);
}


/////////////////////////////////////////////////////////code clean
void display_port_mirroring_config_from_db(int serial_port, int show_prompt)
{
  sqlite3 *db;
  sqlite3_stmt *stmt;
  int rc = sqlite3_open(DB_PATH, &db);
  sqlite3_busy_timeout(db, 2000); 
 
  if (rc)
  {
    printf("\n cannot open database: %s\n", sqlite3_errmsg(db));
    return;
  }
    const char *sql =
        "SELECT di.InterfaceId, di.InterfaceIsMirroring, di.InterfaceName, "
        "mi.InterfaceName AS MonitorInterfaceName, "
        "di.InterfaceMirrorSetting, di.MirrorType, di.Value "
        "FROM DeviceInterfaces di "
        "LEFT JOIN DeviceInterfaces mi ON di.InterfaceToMonitorInterfaceId = mi.InterfaceId";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
      printf("\nError query: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return;
    }
    print_port_mirroring_header();
    int idx = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        print_port_mirroring_row(stmt, idx++);
    }

    if (show_prompt) {
        printf("Press Enter to return to menu...");
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void print_port_mirroring_header() {
    printf("\n=============================================================================================================================================================================================================+\n");
    printf("| %-3s | %-15s | %-10s | %-22s | %-22s | %-50s | %-62s |\n",
           "No", "InterfaceName", "Mirroring", "Monitor Interface ID", "MirrorSetting", "MirrorType", "Value");
    printf("|=====|=================|============|========================|========================|====================================================|================================================================|\n");
}

void print_port_mirroring_row(sqlite3_stmt *stmt, int idx) {
    int mirroring = sqlite3_column_int(stmt, 1);
    const unsigned char *interface_name = sqlite3_column_text(stmt, 2);
    const unsigned char *monitor_name = sqlite3_column_text(stmt, 3);
    const unsigned char *setting = sqlite3_column_text(stmt, 4);
    const unsigned char *type = sqlite3_column_text(stmt, 5);
    const unsigned char *value = sqlite3_column_text(stmt, 6);

    const char *mirroring_str = mirroring ? "Active" : "Inactive";
    const char *interface_name_str = interface_name ? (const char *)interface_name : "";
    const char *monitor_name_str = monitor_name ? (const char *)monitor_name : "N/A";
    const char *setting_str = setting ? (const char *)setting : "";
    char cleaned_type[512] = "";
    if (type)
        clean_json_array_string((const char *)type, cleaned_type, sizeof(cleaned_type));
    else
        strcpy(cleaned_type, "");

    const char *value_str = value ? (const char *)value : "";

    char extracted_values[512] = "";
    if (value_str && strlen(value_str) > 0)
        extract_json_values(value_str, extracted_values, sizeof(extracted_values));
    
    printf("| %-3d | %-15s | %-10s | %-22s | %-22s |", idx, interface_name_str, mirroring_str, monitor_name_str, setting_str);

    // In MirrorType và Value xuống dòng nếu dài
    int max_width_type = 50;
    int max_width_value = 62;

    // In phần đầu tiên của MirrorType
    printf(" %-*.*s |", max_width_type, max_width_type, cleaned_type);

    printf(" %-*.*s |\n", max_width_value, max_width_value, extracted_values);

    // In phần tiếp theo nếu MirrorType hoặc Value dài
    int type_len = strlen(cleaned_type);
    int value_len = strlen(extracted_values);
    int line = 1;
    while (line * max_width_type < type_len || line * max_width_value < value_len) {
        printf("| %-3s | %-15s | %-10s | %-22s | %-22s |", "", "", "", "", "");
        if (line * max_width_type < type_len)
            printf(" %-*.*s |", max_width_type, max_width_type, cleaned_type + line * max_width_type);
        else
            printf(" %-*s |", max_width_type, "");
        if (line * max_width_value < value_len)
            printf(" %-*.*s |\n", max_width_value, max_width_value, extracted_values + line * max_width_value);
        else
            printf(" %-*s |\n", max_width_value, "");

        line++;
    }