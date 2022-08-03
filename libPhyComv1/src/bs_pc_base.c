/*
 * Copyright 2018 Oticon A/S
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "bs_pc_base_types.h"
#include "bs_pc_base.h"
#include "bs_tracing.h"
#include "bs_oswrap.h"
#include "bs_string.h"
#include <signal.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

bool is_base_com_initialized = false; //Used by the BackChannel to avoid deadlocks
char *pb_com_path = NULL;
int pb_com_path_length = 0;

/**
 * Create a FIFO if it doesn't exist
 *
 * Note that it may already exist, and/or that some other program
 * may be racing to create at the same time
 */
int pb_create_fifo_if_not_there(const char *fifo_path) {
  if ((access(fifo_path, F_OK) == -1) && (mkfifo(fifo_path, S_IRWXG | S_IRWXU) != 0) && (access(fifo_path, F_OK) == -1)) {
    bs_trace_warning_line("Can not create %s\n", fifo_path);
    return -1;
  }
  return 0;
}

/**
 * Create the comm folder if it doesn't exist
 * And sets its name in cb_com_path
 * Returns
 *   the length of the cb_com_path string if it succeeds
 *   -1 otherwise
 */
int pb_create_com_folder(const char *s) {
  char *UserName;
  int UserNameLength = 0;
  struct passwd *pw;

  pw = getpwuid(geteuid());
  if (pw != NULL) {
    UserName = pw->pw_name;
  } else {
    bs_trace_error_line("Couldn't get the user name to build the tmp path for the interprocess comm (this shouldn't have happened)\n");
  }

  UserNameLength = strlen(UserName);

  pb_com_path = (char*)bs_calloc(10 + strlen(s) + UserNameLength, sizeof(char));

  sprintf(pb_com_path, "/tmp/bs_%s", UserName);

  if (bs_createfolder(pb_com_path) != 0) {
    free(pb_com_path);
    pb_com_path = NULL;
    return -1;
  }
  sprintf(&pb_com_path[8+UserNameLength], "/%s", s);
  if (bs_createfolder(pb_com_path) != 0) {
    free(pb_com_path);
    pb_com_path = NULL;
    return -1;
  }
  return 9 + UserNameLength + strlen(s);
}

void pb_send_payload(int ff, void *buf, size_t size) {
  if (size) {
    if (buf==NULL) {
      bs_trace_error_line("Null pointer!!\n");
    }
    write(ff, buf, size);
  }
}

//#define NO_LOCK_FILE

#if !defined(NO_LOCK_FILE)
static void lock_file_fill(const char *filename, long int my_pid){
  FILE *file;

  file = bs_fopen(filename, "w");
  fprintf(file, "%li\n",(long) my_pid);
#if defined(__linux)
  long long unsigned int starttime = bs_get_process_start_time(my_pid);
  fprintf(file,"%llu\n",starttime);
#endif
  fclose(file);
}
#endif

/**
 * Check if the lock file exists
 *  * If it doesn't create one for us
 *  * If the lock file exists:
 *    * If the process who created it is still running, we stop.
 *    * If the process who created it is not running, we print a warning and risk it
 *    * If we cannot determine who created it, we stop.
 *
 * Returns 0 if we consider it safe enough to continue
 *         Something else otherwise
 */
static int test_and_create_lock_file(const char *filename) {
#if !defined(NO_LOCK_FILE)
  pid_t my_pid = getpid();

  if (access(filename, F_OK) == -1) {
    // The file does not exist. So unless somebody is racing us, we are safe to go
    lock_file_fill(filename, my_pid);
    return 0;
  }

  bs_trace_warning_line("Previous lock file found %s\n", filename);

  FILE *file;
  bool corrupt_file = false;
  int other_dead = 1;
  long int his_pid;
#if defined(__linux)
  long long unsigned int his_starttime;
#endif

  file = bs_fopen(filename, "r");
  if ( fscanf(file, "%li\n", &his_pid) != 1 ) {
    corrupt_file = true;
  }
#if defined(__linux)
  if ((corrupt_file == false) && (fscanf(file,"%llu\n", &his_starttime) != 1)) {
    corrupt_file = true;
  }
#endif

  fclose(file);

  if (corrupt_file) { //We are provably racing the other process, we stop
    bs_trace_warning_line("Found previous lock owned by unknown process, we may be racing each other => aborting\n");
    return 1;
  }

  other_dead = kill(his_pid, 0);

  if (other_dead == 0) { //a process with the pid exists
#if defined(__linux)
    /* To be sure the pid was not reused, let's check that the process start time matches */

    uint64_t other_start_time = bs_get_process_start_time(his_pid);
    if (his_starttime == other_start_time) { //it is the same process
      bs_trace_warning_line("Found a previous, still RUNNING process w pid %li with the same sim_id and device port which would interfere with this one, aborting\n", his_pid);
    } else {
      other_dead = 1;
    }
#else
    bs_trace_warning_line("Found a previous, still RUNNING process w pid %li with the same sim_id and device port which would interfere with this one, aborting\n", his_pid);
#endif
  }

  if (other_dead){
    bs_trace_warning_line("Found previous lock owned by DEAD process (pid was %li), will attempt to take over\n", his_pid);
    lock_file_fill(filename, my_pid);
    return 0;
  } else {
    return 1;
  }

#else
  return 0;
#endif
}

static void remove_lock_file(char** file_path){
  if (*file_path) {
    remove(*file_path);
    free(*file_path);
    *file_path = NULL;
  }
}

static int phy_test_and_create_lock_file(pb_phy_state_t *self, const char *phy_id){
  int flen = pb_com_path_length + 20 + strlen(phy_id);
  self->lock_path = (char*) bs_calloc(flen, sizeof(char));
  sprintf(self->lock_path, "%s/%s.phy.lock", pb_com_path, phy_id);

  int ret = test_and_create_lock_file(self->lock_path);
  if (ret) {
    free(self->lock_path);
    self->lock_path = NULL;
  }
  return ret;
}

static int device_test_and_create_lock_file(pb_dev_state_t *self, const char *phy_id, unsigned int dev_nbr){
  int flen = pb_com_path_length + 20 + strlen(phy_id) + bs_number_strlen(dev_nbr);

  self->lock_path = (char*) bs_calloc(flen, sizeof(char));

  sprintf(self->lock_path, "%s/%s.d%i.lock", pb_com_path, phy_id, dev_nbr);
  int ret = test_and_create_lock_file(self->lock_path);
  if (ret) {
    free(self->lock_path);
    self->lock_path = NULL;
  }
  return ret;
}


/**
 * Initialize the communication with the devices:
 *
 * inputs:
 *  self Pointer to structure where the connection status will be kept.
 *        MUST be initialized with zeroes.
 *  s    String identifying the simulation
 *  p    String identifying this phy in this simulation
 *  n    How many devices we expect during the simulation
 *
 * returns:
 *   0 if ok. Any other number on error
 */
int pb_phy_initcom(pb_phy_state_t *self, const char* s, const char *p, uint n) {

  signal(SIGPIPE, SIG_IGN);

  if (self->device_connected) {
    bs_trace_warning_line("%s called twice in a simulation\n", __func__);
    return -1;
  }

  pb_com_path_length = pb_create_com_folder(s);

  self->device_connected = NULL;
  self->lock_path = NULL;

  if ( phy_test_and_create_lock_file(self, p) ) {
    return -1;
  }

  self->n_devices = n;
  self->device_connected = (bool *) bs_calloc(n, sizeof(bool));
  self->ff_path_dtp = (char **) bs_calloc(n, sizeof(char *));
  self->ff_path_ptd = (char **) bs_calloc(n, sizeof(char *));
  self->ff_dtp = (int *) bs_calloc(n, sizeof(int *));
  self->ff_ptd = (int *) bs_calloc(n, sizeof(int *));

  for (int d = 0; d < self->n_devices; d++) {
    int flen = pb_com_path_length + 30 + strlen(p) + bs_number_strlen(d);
    self->ff_path_dtp[d] = (char *)bs_calloc(flen, sizeof(char));
    self->ff_path_ptd[d] = (char *)bs_calloc(flen, sizeof(char));
    sprintf(self->ff_path_dtp[d], "%s/%s.d%i.dtp", pb_com_path, p, d);
    sprintf(self->ff_path_ptd[d], "%s/%s.d%i.ptd", pb_com_path, p, d);

    if ((pb_create_fifo_if_not_there(self->ff_path_dtp[d]) != 0)
        || (pb_create_fifo_if_not_there(self->ff_path_ptd[d]) != 0)) {
      pb_phy_disconnect_devices(self);
      bs_trace_error_line("Could not create FIFOs to device %i\n", d);
    }

    if ((self->ff_ptd[d] = open(self->ff_path_ptd[d], O_WRONLY)) == -1) {
      self->ff_ptd[d] = 0;
      pb_phy_disconnect_devices(self);
      bs_trace_error_line("Opening FIFO from phy to device %i failed\n", d);
    }
    if ((self->ff_dtp[d] = open(self->ff_path_dtp[d], O_RDONLY)) == -1) {
      self->ff_dtp[d] = 0;
      pb_phy_disconnect_devices(self);
      bs_trace_error_line("Opening FIFO from device %i to phy failed\n", d);
    }

    self->device_connected[d] = true;
  }

  return 0;
}

void pb_phy_free_one_device(pb_phy_state_t *self, int d) {
  if (self->ff_dtp[d]) {
    close(self->ff_dtp[d]);
    self->ff_dtp[d] = 0;
  }
  if (self->ff_path_dtp[d]) {
    remove(self->ff_path_dtp[d]);
    free(self->ff_path_dtp[d]);
    self->ff_path_dtp[d] = NULL;
  }
  if (self->ff_ptd[d]) {
    close(self->ff_ptd[d]);
    self->ff_ptd[d] = 0;
  }
  if (self->ff_path_ptd[d]) {
    remove(self->ff_path_ptd[d]);
    free(self->ff_path_ptd[d]);
    self->ff_path_ptd[d] = NULL;
  }
  self->device_connected[d] = false;
}

/**
 * Disconnect all devices we are still connected to,
 * free all the memory we used and delete the FIFOs
 *
 * It is safe to call this function multiple times
 */
void pb_phy_disconnect_devices(pb_phy_state_t *self) {

  if (self->device_connected != NULL) {
    pc_header_t header = PB_MSG_DISCONNECT;
    for (int d = 0; d < self->n_devices; d++) {
      if (self->ff_ptd[d]) {
        write(self->ff_ptd[d], &header, sizeof(header));
      }
      pb_phy_free_one_device(self, d);
    }

    if (pb_com_path) {
      rmdir(pb_com_path);
      free(pb_com_path);
      pb_com_path = NULL;
    }

    if (self->device_connected) {
      free(self->device_connected);
      self->device_connected = NULL;
    }
    if (self->ff_path_dtp) {
      free(self->ff_path_dtp);
      self->ff_path_dtp = NULL;
    }
    if (self->ff_dtp) {
      free(self->ff_dtp);
      self->ff_dtp = NULL;
    }
    if (self->ff_path_ptd) {
      free(self->ff_path_ptd);
      self->ff_path_ptd = NULL;
    }
    if (self->ff_ptd) {
      free(self->ff_ptd);
      self->ff_ptd = NULL;
    }
  }
  remove_lock_file(&self->lock_path);
}

/**
 * Check if we are connected to this device (or any device)
 * Return 1 if we are
 */
int pb_phy_is_connected_to_device(pb_phy_state_t *self, uint d){
  if ((self->device_connected == NULL) || (!self->device_connected[d])) {
    bs_trace_error_line("Programming error while trying to talk to device %i\n", d);
    return 0;
  }
  return 1;
}

/**
 * Respond to the device at the end of wait
 */
void pb_phy_resp_wait(pb_phy_state_t *self, uint d) {
  if ( pb_phy_is_connected_to_device(self, d) ) {
    pc_header_t header = PB_MSG_WAIT_END;
    write(self->ff_ptd[d], &header, sizeof(header));
  }
}

/**
 * Get (and return) the next request from this device
 */
pc_header_t pb_phy_get_next_request(pb_phy_state_t *self, uint d) {
  pc_header_t header = PB_MSG_DISCONNECT;

  if ( pb_phy_is_connected_to_device(self, d) ) {
    int n = read(self->ff_dtp[d], &header, sizeof(header));
    if (n < sizeof(header)) {
      bs_trace_warning_line("Device %u left the party unsuspectingly.. I treat it as if it disconnected\n", d);
    }

    if ((header == PB_MSG_DISCONNECT) || (header == PB_MSG_TERMINATE)) {
      //if the read failed or the device really wants to disconnect
      pb_phy_free_one_device(self, d);
    }
  }
  return header;
}

void pb_phy_get_wait_s(pb_phy_state_t *self, uint d, pb_wait_t *wait_s) {
  if ( pb_phy_is_connected_to_device(self, d) ) {
    read(self->ff_dtp[d], wait_s, sizeof(pb_wait_t));
  }
}

/**
 * Initialize the communication interface with the phy
 *
 * inputs:
 *  self  Pointer to structure where the connection status will be keeps.
 *         MUST be initialized with zeroes.
 *  d     The device number this device will have in this phy
 *  s     String identifying the simulation
 *  p     String identifying this phy in this simulation
 *
 * returns:
 *   0 if ok. Any other number on error
 */
int pb_dev_init_com(pb_dev_state_t *self, uint d, const char* s, const char *p) {

  if (self->connected) {
    bs_trace_warning_line("%s called twice in a simulation\n", __func__);
    return -1;
  }

  /* In case we fail, we initialize them to "invalid" content*/
  self->ff_path_dtp = NULL;
  self->ff_path_ptd = NULL;

  self->ff_ptd = 0; /*0 == stdin == not one we would have used */
  self->ff_dtp = 0;

  if ((s == NULL) || (p  == NULL)) {
    bs_trace_error_line("The simulation and phy identification strings need to be provided\n");
  }

  self->this_dev_nbr = d;
  pb_com_path_length = pb_create_com_folder(s);

  if ( device_test_and_create_lock_file(self, p, d) ) {
    bs_trace_error_line("Failed to get lock\n");
  }

  int flen = pb_com_path_length + strlen(p) + bs_number_strlen(d) + 30;
  self->ff_path_dtp = (char *) bs_calloc(flen, sizeof(char));
  self->ff_path_ptd = (char *) bs_calloc(flen, sizeof(char));
  sprintf(self->ff_path_dtp, "%s/%s.d%i.dtp", pb_com_path, p, d);
  sprintf(self->ff_path_ptd, "%s/%s.d%i.ptd", pb_com_path, p, d);

  if ((pb_create_fifo_if_not_there(self->ff_path_dtp) != 0)
      || (pb_create_fifo_if_not_there(self->ff_path_ptd) != 0)) {
    pb_dev_clean_up(self);
    bs_trace_error_line("Could not create FIFOs");
  }

  if (((self->ff_ptd = open(self->ff_path_ptd, O_RDONLY )) == -1)) {
    self->ff_ptd = 0;
    pb_dev_clean_up(self);
    bs_trace_error_line("Opening FIFO from phy to device failed\n");
  }
  if (((self->ff_dtp = open(self->ff_path_dtp, O_WRONLY )) == -1)) {
    self->ff_dtp = 0;
    pb_dev_clean_up(self);
    bs_trace_error_line("Opening FIFO from device to phy failed\n");
  }

  self->connected = true;
  is_base_com_initialized = true;
  return 0;
}

/**
 * Attempt to terminate the simulation and disconnect
 */
void pb_dev_terminate(pb_dev_state_t *self) {
  if (self->connected) {
    pc_header_t header = PB_MSG_TERMINATE;

    write(self->ff_dtp, &header, sizeof(header));
    pb_dev_clean_up(self);
  }
}

/**
 * Disconnect from the phy
 */
void pb_dev_disconnect(pb_dev_state_t *self) {
  if (self->connected) {
    pc_header_t header = PB_MSG_DISCONNECT;

    write(self->ff_dtp, &header, sizeof(header));
    pb_dev_clean_up(self);
  }
}

/*
 * Try to delete the FIFOs, clear memory and try to delete the directory
 *
 * It is safe to call this function (unnecessarily) several times
 */
void pb_dev_clean_up(pb_dev_state_t *self) {

  remove_lock_file(&self->lock_path);

  self->connected = false; //we don't want any possible future call to libphycom to attempt to talk with the phy

  if (self->ff_path_dtp) {
    if (self->ff_dtp) {
      close(self->ff_dtp);
      self->ff_dtp = 0;
    }

    remove(self->ff_path_dtp);
    free(self->ff_path_dtp);
    self->ff_path_dtp = NULL;
  }

  if (self->ff_path_ptd) {
    if (self->ff_ptd) {
      close(self->ff_ptd);
      self->ff_ptd = 0;
    }
    remove(self->ff_path_ptd);
    free(self->ff_path_ptd);
    self->ff_path_ptd = NULL;
  }

  if (pb_com_path != NULL) {
    rmdir(pb_com_path);
    free(pb_com_path);
    pb_com_path = NULL;
  }
}

/**
 * Read from a FIFO n_bytes
 * returns -1 on failure (it can't read n_bytes, and cleans up),
 * otherwise returns n_bytes
 */
int pb_dev_read(pb_dev_state_t *self, void *buf, size_t n_bytes) {
  int read_b;

  read_b = read(self->ff_ptd, buf, n_bytes);

  if (n_bytes == read_b) {
    return read_b;
  }

  bs_trace_warning_line(COM_FAILED_ERROR " (tried to get %i got %i bytes)\n", n_bytes, read_b);
  pb_dev_clean_up(self);
  return -1;
}

/**
 * Request a non blocking wait to the phy
 * Note that eventually the caller needs to pick the wait response
 * from the phy with cb_dev_pick_wait_resp()
 */
int pb_dev_request_wait_nonblock(pb_dev_state_t *self, pb_wait_t *wait_s) {
  CHECK_CONNECTED(self->connected);
  pb_send_msg(self->ff_dtp, PB_MSG_WAIT, (void *)wait_s, sizeof(pb_wait_t));
  return 0;
}

/**
 * Block until getting a wait response from the phy
 * If everything goes ok, the phy has just reached the
 * requested end time and 0 is returned
 * Otherwise, we should disconnect (-1 will be returned)
 */
int pb_dev_pick_wait_resp(pb_dev_state_t *self) {
  CHECK_CONNECTED(self->connected);

  pc_header_t header = PB_MSG_DISCONNECT;

  if (pb_dev_read(self, &header, sizeof(header)) == -1) {
    return -1;
  }

  if (header == PB_MSG_DISCONNECT) {
    pb_dev_clean_up(self);
    return -1;
  } else if (header == PB_MSG_WAIT_END) {
    return 0;
  } else {
    INVALID_RESP(header);
    return -1;
  }
}

/**
 * Request a wait to the phy and block until receiving the response
 * If everything goes ok 0 is returned
 *
 * Otherwise, we should disconnect (-1 will be returned)
 */
int pb_dev_request_wait_block(pb_dev_state_t *self, pb_wait_t *wait_s) {
  CHECK_CONNECTED(self->connected);
  int ret;
  ret = pb_dev_request_wait_nonblock(self, wait_s);
  if (ret)
    return ret;
  return pb_dev_pick_wait_resp(self);
}
