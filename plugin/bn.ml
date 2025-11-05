open Binsec
open Libsse
open Types
open BnScript

module Macros = Map.Make(String)

module Loc = Ast.Loc

type Ast.t += Def_macro of string * string option list * Ast.Instr.t list 

type Ast.Instr.t += PushBN of (Ast.Expr.t Ast.loc)
                 | PushBV of (Ast.Expr.t Ast.loc)
                 | PopBN of (Ast.Expr.t Ast.loc)
                 | PopBV of (Ast.Expr.t Ast.loc)
                 | AddBN | SubBN | MulBN | DivUBN | DivSBN
                 | ModUBN | ModSBN | OrBN | AndBN | XorBN
                 | Concat | LShiftBN | RShiftUBN | RShiftSBN
                 | EqBN | DiffBN | LeqUBN | LtUBN | GeqUBN | GtUBN
                 | LeqSBN | LtSBN | GeqSBN | GtSBN
                 | Call_macro of string * (Ast.Expr.t Ast.loc * string) list

include Cli.Make (struct
    let name = "Extension with Builtins with Big Number"
    let shortname = "bn"
  end)

module Backend = Builder.Variant_choice_assoc (struct
  type t = [ `Openssl | `Bearssl ]
  let name = "backend"
  let doc  = "Big-number backend: openssl | bearssl"
  let default   = `Bearssl
  let assoc_map = [ "openssl", `Openssl; "bearssl", `Bearssl ]
end)

module KeyLength = Builder.Integer (struct
    let doc = "Key length in bits"
    let name = "keylen"
    let default = 1024
  end)

let backend_ref : (module CryptoBN.CryptoBN) ref =
  ref (module Bearsslbn.BearSSLBN : CryptoBN.CryptoBN)

let set_backend = function
  | `Openssl ->
    Format.printf "OpenSSL is chosen";
    backend_ref := (module Opensslbn.OpenSSLBN : CryptoBN.CryptoBN)
  | `Bearssl -> backend_ref := (module Bearsslbn.BearSSLBN  : CryptoBN.CryptoBN)

let set_keylen n =
  Format.printf "%d is chosen as key len" n;
  CryptoBN.key_size := n

let grammar_extension =
  [
        Dyp.Add_rules
          [
            ( ( "decl",
            [
              Dyp.Regexp (RE_String "def_macro");
              Dyp.Non_ter ("ident", No_priority);
              Dyp.Regexp (RE_Char '(');
              Dyp.Non_ter ("comma_separated_arg_rev_list", No_priority);
              Dyp.Regexp (RE_Char ')');
              Dyp.Non_ter ("stmts", No_priority);
              Dyp.Regexp (RE_String "end");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _;
                    Libparser.Syntax.String macro_name;
                    _;
                    Libparser.Syntax.Obj (Script.Loc_opt_list args);
                    _ ;
                    Libparser.Syntax.Stmt stmts;
                    _]
                  ->
                  let params = List.map
                       (fun arg ->
                         match arg with
                           Some (Loc.Var (a,_),_) -> Some a
                         | _ -> None
                          )
                       (List.rev args) in
                       
                       ( Libparser.Syntax.Decl (Def_macro (macro_name, params, stmts)), [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "call_macro");
              Dyp.Non_ter ("ident", No_priority);
              Dyp.Regexp (RE_Char '(');
              Dyp.Non_ter  ("comma_separated_named_rev_list", No_priority);
              Dyp.Regexp (RE_Char ')');
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _; Libparser.Syntax.String str; _;
                    Libparser.Syntax.Obj (Script.Named_list args);
                    _;
                  ]
                  ->
                  ( Libparser.Syntax.Instr (Call_macro (str, List.rev args)),
                          [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "pushBN");
              Dyp.Non_ter ("named", No_priority);
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _; Libparser.Syntax.Obj (Script.Named (expr,_)) ]
                  ->
                  ( Libparser.Syntax.Instr (PushBN expr),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "pushBV");
              Dyp.Non_ter ("named", No_priority);
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _; Libparser.Syntax.Obj (Script.Named (expr,_)) ]
                  ->
                  ( Libparser.Syntax.Instr (PushBV expr),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "popBV");
              Dyp.Non_ter ("named", No_priority);
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _; Libparser.Syntax.Obj (Script.Named (expr,_)) ]
                  ->
                  ( Libparser.Syntax.Instr (PopBV expr),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "popBN");
              Dyp.Non_ter ("named", No_priority);
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _;  Libparser.Syntax.Obj (Script.Named (expr,_)) ]
                  ->
                  ( Libparser.Syntax.Instr (PopBN expr),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "addBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (AddBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "subBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (SubBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "mulBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (MulBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "divUBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (DivUBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "divSBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (DivSBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "modUBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (ModUBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "modSBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (ModSBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "orBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (OrBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "andBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (AndBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "xorBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (XorBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "leftShiftBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (LShiftBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "rightUShiftBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (RShiftUBN),
                    [] )
                | _ -> assert false );
            ( ( "fallthrough",
            [
              Dyp.Regexp (RE_String "rightSShiftBN");
            ],
            "default_priority",
            [] ),
              fun _ -> function
                | [ _ ]
                  ->
                  ( Libparser.Syntax.Instr (RShiftSBN),
                    [] )
                | _ -> assert false );
          ];
      ]


let instruction_printer = Some
          (fun ppf -> function
             | Call_macro (name, l_args) ->
               Format.fprintf ppf "call_macro %s(%a)"
                 name
                 (Format.pp_print_list
                    ~pp_sep:(fun ppf () -> Format.pp_print_string ppf ", ")
                    (fun ppf ((expr,_), str) ->
                       Format.fprintf ppf "%a as %s" Ast.Expr.pp expr str))
                  l_args;
               true
             | PushBN (s, _) -> Format.fprintf ppf "PushBN %a" Ast.Expr.pp s; true
             | PushBV (s, _) -> Format.fprintf ppf "PushBV %a" Ast.Expr.pp s; true
             | PopBV (s, _) -> Format.fprintf ppf "PopBV %a" Ast.Expr.pp s; true
             | PopBN  (s, _)  -> Format.fprintf ppf "PopBN %a" Ast.Expr.pp s; true
             | AddBN -> Format.fprintf ppf "AddBN"; true
             | SubBN -> Format.fprintf ppf "SubBN"; true
             | MulBN -> Format.fprintf ppf "MulBN"; true
             | DivUBN -> Format.fprintf ppf "DivUBN"; true
             | DivSBN -> Format.fprintf ppf "DivSBN"; true
             | ModUBN -> Format.fprintf ppf "ModUBN"; true
             | ModSBN -> Format.fprintf ppf "ModSBN"; true
             | OrBN -> Format.fprintf ppf "OrBN"; true
             | AndBN -> Format.fprintf ppf "AndBN"; true
             | XorBN -> Format.fprintf ppf "XorBN"; true
             | LShiftBN -> Format.fprintf ppf "LShiftBN"; true
             | RShiftUBN -> Format.fprintf ppf "RShiftUBN"; true
             | RShiftSBN -> Format.fprintf ppf "RShiftSBN"; true
             | _ -> false
      )            

let () =
  
  Exec.register_plugin (
    module struct
      module BN = struct
        let pushBN env st e =
          let module M = (val !backend_ref : CryptoBN.CryptoBN) in
          M.pushBN env st e
        let popBN env st e =
          let module M = (val !backend_ref : CryptoBN.CryptoBN) in
          M.popBN env st e
      end

      let name = "bn"
      let grammar_extension = grammar_extension
      let declaration_printer = Some
        (fun ppf -> function
               Def_macro (name, _, l_instrs) ->
               Format.fprintf ppf "def %s( ... )\n%a\nend"
                 name
                 (Format.pp_print_list
                    ~pp_sep:(fun ppf () -> Format.pp_print_string ppf ", ")
                    (fun ppf instr -> Script.Instr.pp ppf instr))
                 l_instrs;
                  true
             | _ -> false
        )
      let instruction_printer = instruction_printer
      let extension :
        type a b.
        (module EXPLORATION_STATISTICS) ->
        (module Path.S with type t = a) ->
        (module STATE with type t = b) ->
        (module Exec.EXTENSION with type path = a and type state = b) option =
        fun _stats path state ->
        if is_enabled () then (
          set_backend (Backend.get ());
        set_keylen (KeyLength.get ());
          Some (module struct
            module P = (val path)
            module S = (val state)
            type path  = P.t
            and  state = S.t
            let macros = ref Macros.empty
            let bv_stack = Stack.create ()
                
            let initialization_callback = None
              
            let declaration_callback = Some
              (fun decl _ _ state ->
                   match decl with
                   | Def_macro (macro_name, l_params, l_instrs) ->
                     macros := Macros.add macro_name (l_params, l_instrs) !macros;
                     Some state  
                   | _ -> None ) 
              ;;

            let translate_instr_to_ir env = function
                Ast.Instr.Nop -> Ir.Nop
              | Ast.Instr.Assign (lval, rval) ->
                begin
                  let lval = eval_loc lval env in
                  let rval =
                    eval_expr ~size:(Dba.LValue.size_of lval) rval env
                  in
                  match lval with
                  | Var var ->  
                    let r = Ir.Assign { var; rval } in
                    r
                  | Store (_, dir, addr, base) ->
                    let r = Ir.Store {base; dir; addr; rval} in
                    r
                  | Restrict (_, _) ->
                    failwith "Not supported Sub"
                end
              | _ -> failwith "Not supported instruction"
            ;;

            let mk_bv_op_instr op =
              let v2 = Stack.pop bv_stack in
              let v1 = Stack.pop bv_stack in
              let ip1 = Ir.Print (Output.Value (Output.Hex, v2)) in
              let ip2 = Ir.Print (Output.Value (Output.Hex, v1)) in
              let rval  = Dba.Expr.binary op v1 v2 in
              let var : Dba.Var.t  = Dba.Var.create "bvtmp" ~bitsize:(Size.Bit.create !CryptoBN.key_size) ~tag:Dba.Var.Tag.Temp in
              Stack.push (Dba.Expr.v var) bv_stack;
              let bv_op_instr = Ir.Assign {var; rval} in
              let ip = Ir.Print (Output.Value (Output.Hex, Dba.Expr.v var)) in
              (* Format.printf "%a\n" Ir.pp_fallthrough bv_op_instr; *)
              [ip1;ip2;bv_op_instr;ip]
            
            let instruction_callback =
              Some
                (fun decl env ->
                   match decl with
                   | Call_macro (macro_name, l_args) ->  
                     let (l_params, l_instrs) = try Macros.find macro_name !macros with Not_found -> raise Not_found in
                     let subs_pairs : (string option * string) list = List.combine l_params (List.map snd l_args) in
                     let l_subs_instrs =
                       List.fold_left (fun a_l_instrs (o_param, arg) ->
                           match o_param with
                             Some param ->
                                 List.map (subs (param, arg)) a_l_instrs
                           | _ ->
                             a_l_instrs
                         ) l_instrs subs_pairs in
                     let l_irs = List.map (translate_instr_to_ir env) l_subs_instrs in
                     l_irs
                   | PushBV bvx ->
                     let var = eval_expr bvx env in
                     Stack.push var bv_stack;
                     [Ir.Nop]
                   | PopBV bvx ->
                     let rval = Stack.pop bv_stack in
                     let var = eval_expr bvx env in
                     (match var with
                      Expr.Var var ->
                      [Ir.Assign {var;rval}]
                      | _ -> failwith "It is not a variable"
                     )
                   | PushBN bnp ->
                     BN.pushBN env bv_stack bnp
                   | PopBN bnp' ->
                     BN.popBN env bv_stack bnp'
                   | AddBN ->
                     mk_bv_op_instr Dba.Binary_op.Plus
                   | SubBN ->
                     mk_bv_op_instr Dba.Binary_op.Minus
                   | MulBN ->
                     mk_bv_op_instr Dba.Binary_op.Mult
                   | DivUBN->
                     mk_bv_op_instr Dba.Binary_op.DivU
                   | DivSBN ->
                     mk_bv_op_instr Dba.Binary_op.DivS
                   | ModUBN ->
                     mk_bv_op_instr Dba.Binary_op.ModU
                   | ModSBN ->
                     mk_bv_op_instr Dba.Binary_op.ModS
                   | OrBN ->
                     mk_bv_op_instr Dba.Binary_op.Or
                   | AndBN ->
                     mk_bv_op_instr Dba.Binary_op.And
                   | XorBN ->
                     mk_bv_op_instr Dba.Binary_op.Xor
                   | LShiftBN ->
                     mk_bv_op_instr Dba.Binary_op.LShift
                   | RShiftUBN ->
                     mk_bv_op_instr Dba.Binary_op.RShiftU
                   | RShiftSBN ->
                     mk_bv_op_instr Dba.Binary_op.RShiftS
                   | _ -> [])
            let process_callback = None
            let builtin_callback = None
            let builtin_printer = None
            let at_exit_callback = None
            end
          ))
        else
          None

    end : Exec.PLUGIN)
    

