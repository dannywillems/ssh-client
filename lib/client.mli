open Types

(** Different kinds of authentication accepted by libssh *)
type auth =
  | Auto  (** Authenticate using the Ssh agent, assuming its running *)
  | Interactive  (** Type in the password on the command line*)

(** Options needed when connecting over ssh *)
type options =
  { host: string;
    username: string;
    port: int;
    log_level: ssh_verbosity;
    auth: auth }

val connect_and_auth : options -> ssh_session -> unit
(** Connect and authenticate a ssh connection *)

val exec : command:string -> ssh_session -> string
(** Execute a remote command, get result as a string *)

(* val with_session : (ssh_session -> 'a) -> options -> 'a *)

val with_shell : (ssh_channel -> 'a) -> ssh_session -> 'a
(** Creates a channel from the given session and requests a shell on it. Warning: no pty is requested. *)

val scp :
  src_path:string ->
  base_path:string ->
  dst_filename:string ->
  mode:int ->
  ssh_session ->
  unit
