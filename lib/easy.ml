open Batteries

open Types

type auth =
  | Auto
  | Interactive

type options =
  { host      : string;
    username  : string;
    port      : int;
    log_level : ssh_verbosity }

type shell_handle = ssh_channel

(* TODO *)

let check_else msg res =
  match res with
  | SSH_OK ->
    Printf.eprintf "%s: success\n%!" msg
  | _ ->
    failwith msg
      
  (* match session_code with
   * | SSH_OK    -> ()
   * | SSS_ERROR ->
   * | SSH_AGAIN
   * | SSH_EOF *)
let authcheck = ignore

(* Since we don't do any smart error recovery, we just wrap Raw.* functions in a generic
   error catching function *)
let options_set session option =
  check_else (Printf.sprintf "options_set: %s" (ssh_option_to_string option))
    (Raw.Session.options_set session option)

let channel_open_session channel =
  check_else "channel_open_session" (Raw.Channel.open_session channel)

let channel_request_shell channel =
  check_else "channel_request_shell" (Raw.Channel.request_shell channel)

let channel_close channel =
  check_else "channel_close" (Raw.Channel.close channel)

(* Allocates a channel *)
let with_channel ~session f =
  let chan = Raw.Channel.new_ session in
  let free_and_continue channel k =
    Raw.Channel.free chan;
    k ()
  in
  let res =
    try f chan with
    | e ->
      free_and_continue chan (fun () -> raise e)
  in
  free_and_continue chan (fun () -> res)
  

let with_session ~channel f =
  match Raw.Channel.open_session channel with
  | SSH_OK ->
    let close_and_continue channel k =
      match Raw.Channel.close channel with
      | SSH_OK ->
        k ()
      | _ ->
        failwith "with_channel_session: unrecoverable error"
    in
    let result =
      try f () with
      | e -> close_and_continue channel (fun () -> raise e)
    in
    close_and_continue channel (fun () -> result)
  | _ ->
    failwith "with_channel_session: channel could not be opened"

(* creates a fresh channel and initializes it for shell interaction
   on a given session *)
let with_shell_channel ~session f =
  with_channel ~session (fun channel ->
      with_session ~channel (fun () ->
          channel_request_shell channel;
          f channel
        )
    )


(* Peform auth and connection with given password *)
let auth_password ~session ~options:{ host; username; port; log_level } ~password =
  options_set session (SSH_OPTIONS_HOST host);
  options_set session (SSH_OPTIONS_USER username);
  options_set session (SSH_OPTIONS_PORT port);
  options_set session (SSH_OPTIONS_LOG_VERBOSITY log_level);
  check_else "auth_password: connection failed"
    (Raw.Session.connect session);
  match Raw.Userauth.password session username password with
  | SSH_AUTH_SUCCESS -> ()
  | _ ->
    failwith "auth_password: failed to connect - please check logs"

(* Read password from stdin in a stealthy manner *)
let read_password () =
  let open Unix in
  let term_init = tcgetattr stdin in
  let term_no_echo = { term_init with c_echo = false } in
  tcsetattr stdin TCSANOW term_no_echo;
  let password =
    try read_line ()
    with _ ->
      (tcsetattr stdin TCSAFLUSH term_init;
       failwith "read_password: readline failed")
  in 
  tcsetattr stdin TCSAFLUSH term_init;
  password

let input_password ~host ~username =
  Printf.printf "password for %s@%s:%!" username host;
  read_password ()

(* Opens a session in password mode *)
let with_password : options:options -> (ssh_session -> 'a) -> 'a  =
  fun ~options f ->
    (* output/input are from the POV of the ancestor, i.e.
       children write on the input and the ancestor reads the output *)
    let output, input = Unix.pipe () in  
    let this_pid      = Unix.fork () in
    if this_pid < 0 then
      failwith "Easy.with_session: error while forking"
    else if this_pid = 0 then begin
      let ssh_session = Raw.Session.new_ () in
      let password    = input_password options.host options.username in
      auth_password ~session:ssh_session ~options ~password;
      try
        let res = f ssh_session in
        Raw.Session.close ssh_session;
        let input_chan = Unix.out_channel_of_descr input in
        BatMarshal.output input_chan res;
        close_out input_chan;
        exit 0
      with
      | _ ->
        (Raw.Session.close ssh_session;
         let input_chan = Unix.out_channel_of_descr input in
         close_out input_chan;
         exit 1)
    end else begin
      Unix.close input;
      let _, status = Unix.wait () in
      match status with
      | WEXITED 0 ->
        Marshal.input (Unix.in_channel_of_descr output)
      | WEXITED n ->
        let m =
          Printf.sprintf "Easy.with_password: abnormal termination of child process (code %d)" n
        in
        failwith m
      | WSIGNALED n ->
        let m =
          Printf.sprintf "Easy.with_password: abnormal termination of child process (signal %d)" n
        in
        failwith m      
      | WSTOPPED n ->
        let m =
          Printf.sprintf "Easy.with_password: abnormal termination of child process (stopped %d)" n
        in
        failwith m      
    end

let execute ?(read_stderr=false) ?(read_timeout=100) (channel : shell_handle) command =
  match Raw.Channel.write channel (command^"\n") with
  | SSH_OK ->
    Raw.Channel.read_timeout channel read_stderr read_timeout
  | _ ->
    failwith "Easy.execute: error while writing command to channel"


let scp ~session ~src_path ~dst_path ~mode =
  ()
