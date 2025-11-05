open Binsec
open Libsse
    
let key_size : int ref = ref 2048

let prefix_var prefix (v, pos) =
  match v with
    Ast.Expr.Loc (Ast.Loc.Var (s, l),_) -> (Ast.Loc.Var (prefix ^ s, l), pos)
  | _ -> failwith "Invalid Variable"

let get_constants env =
  let dir = env.Script.endianness in
  let bvks i    = Bitvector.create (Z.of_int i) !key_size in
  let bvws i    = Bitvector.create (Z.of_int i) env.wordsize in
  let word_size = Size.Byte.create (env.wordsize/8) in
  let bv32_one  = bvws 1 (* Bitvector.create (Z.of_int 1) (env.wordsize) *) in
  let one       = Dba.Expr.constant bv32_one in
  let bv_zero   = bvks 0 in
  let bv_one    = bvks 1 in
  let bv32_zero = bvws 0 in
  (dir, bvws, word_size, bv32_zero, bv32_one, one, bv_zero, bv_one)
  

module type CryptoBN = sig
  val pushBN : Script.env -> Types.Expr.t Stack.t -> Ast.Expr.t Ast.loc -> Ir.fallthrough list
  val popBN : Script.env -> Types.Expr.t Stack.t -> Ast.Expr.t Ast.loc -> Ir.fallthrough list
end

type t = (module CryptoBN)

module Registry = struct
  let tbl : (string, t) Hashtbl.t = Hashtbl.create 7

  let register name (m : t) =
    Hashtbl.replace tbl name m

  let names () =
    Hashtbl.to_seq_keys tbl |> List.of_seq |> List.sort String.compare
      
  let find_exn name =
    match Hashtbl.find_opt tbl name with
    | Some m -> m
    | None ->
      let available = String.concat ", " (names ()) in
      failwith (Printf.sprintf "Unknown BN backend '%s'. Available: %s" name available)
end

