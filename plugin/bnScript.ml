open Binsec
open Libsse
open Script

exception Invalid_annotation of (Loc.t loc * int * Lexing.position option)
                                
let rec subs_expr ((x, y) as sp) ((e : Expr.t), pos) : Expr.t loc = 
  let f = subs_expr sp in
  let e : Expr.t =
    match e with
    | Int _ 
    | Bv _ -> e
    | Symbol ((name, attr), pos) ->
      if name=x then Symbol ((y, attr), pos) else e 
    | Loc loc ->
      Loc (subs_loc sp loc)
    | Unary (op, x) ->
      Unary (op, f x)
    | Binary (op, x, y) ->
      Binary (op, f x, f y)
    | Ite (q, x, y) ->
      Ite (f q, f x, f y)
  in
  (e, pos)

and subs_loc ((x, y) as sp) (l, pos) =
  let lval =
    match l with
    | Var (name, annot) ->
      if name = x then Loc.Var (y, annot) else l
    | Load (len, endianness, addr, array) ->
      Load (len, endianness, subs_expr sp addr, array)
    | Sub (intv, t') ->
      Sub (intv, subs_loc sp t')
  in
  (lval, pos)
  

let subs sp = function
    Ast.Instr.Assign (lval, rval) ->
    Ast.Instr.Assign (subs_loc sp lval, subs_expr sp rval)
  | a ->
    a

(** from script.ml begins *)
let rec eval_expr ?size ((e, p) as t : Expr.t Script.loc) env =
  let e =
    match e with
    | Int (z,_) ->
      (
        match size with
        | None -> raise (Script.Inference_failure t)
        | Some size ->
          (if Z.numbits z > size then
             let line = p.pos_lnum and column = p.pos_cnum - p.pos_bol - 1 in
             Options.Logger.warning
               "integer %a (line %d, column %d) does not fit in a bitvector \
                of %d bit%s"
               Z.pp_print z line column size
               (if size > 1 then "s" else ""));
          Dba.Expr.constant (Bitvector.create z size))
    | Bv bv ->
      Dba.Expr.constant bv
    | Symbol ((name, attr), _) ->
      env.lookup_symbol name attr
    | Loc (Sub ({ hi; lo }, loc), _) ->
      Dba.Expr.restrict lo hi
        (Dba.LValue.to_expr (eval_loc ?size:None loc env))
    | Loc loc ->
      Dba.LValue.to_expr (eval_loc ?size loc env)
    | Unary (op, x) ->
      let size =
        match op with Restrict _ | Uext _ | Sext _ -> None | _ -> size
      in
      Dba.Expr.unary op (eval_expr ?size x env)
    | Binary (op, x, y) ->
      let x, y = eval_binary ?size ~op x y env in
      Dba.Expr.binary op x y
    | Ite (q, x, y) ->
      let q = eval_expr ~size:1 q env in
      let x, y = eval_binary ?size x y env in
      Dba.Expr.ite q x y
  in
  Option.iter
    (fun size ->
       let size' = Dba.Expr.size_of e in
       if size' <> size then raise (Invalid_size (t, size', size)))
    size;
  e

and eval_binary ?(first = true) ?size ?op x y env =
  match
    eval_expr
      ?size:
        (match op with
         | None -> size
         | Some
             ( Plus | Minus | Mult | DivU | DivS | ModU | ModS | Or | And | Xor
             | LShift | RShiftU | RShiftS | LeftRotate | RightRotate ) ->
           size
         | Some _ -> None)
      x env
  with
  | x ->
    ( x,
      eval_expr
        ?size:
          (match op with
           | Some Concat -> (
               match size with
               | None -> None
               | Some size -> Some (size - Dba.Expr.size_of x))
           | None | Some _ -> Some (Dba.Expr.size_of x))
        y env )
  | exception Inference_failure _ when first ->
    let y, x = eval_binary ~first:false ?size ?op y x env in
    (x, y)

and eval_int ((e, _) as t : Expr.t loc) env =
  match e with
  | Int (z,_) ->
    if not (Z.fits_int z) then raise (Invalid_operation t);
    Z.to_int z
  | Bv bv ->
    if not (Z.fits_int (Bitvector.signed_of bv)) then
      raise (Invalid_operation t);
    Bitvector.to_int bv
  | Symbol ((name, attr), _) -> (
      match env.lookup_symbol name attr with
      | Var { info = Symbol (_, (lazy bv)); _ } ->
        if not (Z.fits_int (Bitvector.value_of bv)) then
          raise (Invalid_operation t);
        Bitvector.to_uint bv
      | _ -> raise (Invalid_operation t))
  | Unary (UMinus, x) -> -eval_int x env
  | Binary (Plus, x, y) -> eval_int x env + eval_int y env
  | Binary (Minus, x, y) -> eval_int x env - eval_int y env
  | Binary (Mult, x, y) -> eval_int x env * eval_int y env
  | Binary (DivS, x, y) -> eval_int x env / eval_int y env
  | Loc _ | Unary _ | Binary _ | Ite _ -> raise (Invalid_operation t)

and declare_var name size pos env =
  let var = Dba.Var.create name ~bitsize:(Size.Bit.create size) ~tag:Empty in
  env.define var pos;
  Dba.LValue.v var

and eval_var ?size ((_, p) as t) name (annot : Ast.Size.t) env =
  let lval =
    match env.lookup name with
    | lval ->
      let size' =
        match annot with
        | Explicit size -> size
        | Sizeof lval ->
          let lval = eval_loc lval env in
          Dba.LValue.size_of lval
        | Eval expr ->
          let size = eval_int expr env in
          if size < 0 then raise (Invalid_operation expr);
          size
        | Implicit -> Dba.LValue.size_of lval
      and size = Dba.LValue.size_of lval in
      if size <> size' then       
        raise (Invalid_annotation (t, size, env.origin name));
      lval
    | exception Not_found ->
      (
        match annot with
        | Explicit size ->
          declare_var name size p env
        | Sizeof lval ->
          let lval = eval_loc lval env in
          declare_var name (Dba.LValue.size_of lval) p env
        | Eval expr ->
          let size = eval_int expr env in
          if size < 0 then raise (Invalid_operation expr);
          declare_var name size p env
        | Implicit ->
          (
            match size with
            | None -> 
              raise (Inference_failure (Expr.loc t, p))
            | Some size ->
              declare_var name size p env))
  in
  Option.iter
    (fun size ->
       let size' = Dba.LValue.size_of lval in
       if size' <> size then raise (Invalid_size ((Expr.loc t, p), size', size)))
    size;
  lval

and eval_loc ?size ((l, p) as t : Loc.t loc) env =
  let lval =
    match l with
    | Var (name, annot) ->
      eval_var ?size t name annot env
    | Load (len, endianness, addr, array) ->
      let endianness =
        Option.fold ~none:env.endianness ~some:Fun.id endianness
      in
      let addr = eval_expr ~size:env.wordsize addr env in
      Dba.LValue.store (Size.Byte.create len) endianness addr ?array
    | Sub ({ hi; lo }, ((Var (name, annot), _) as t')) ->
      (
        match eval_var ?size t' name annot env with
        | Var var -> Dba.LValue.restrict var lo hi
        | Restrict (var, { hi = hi'; lo = lo' }) ->
          if hi' > hi + lo' then raise (Inference_failure (Expr.loc t, p));
          Dba.LValue.restrict var (lo + lo') (hi + lo')
        | _ -> raise (Invalid_operation (Expr.loc t, p)))
    | Sub _ -> raise (Invalid_operation (Expr.loc t, p))
  in
  Option.iter
    (fun size ->
       let size' = Dba.LValue.size_of lval in
       if size' <> size then raise (Invalid_size ((Expr.loc t, p), size', size)))
    size;
  lval

let  lval2exp = function
    Dba.LValue.Var {id=_; name; size; info=_} -> Dba.Expr.var name size
  | Store (sz, endi, e, _) -> Dba.Expr.load (Size.Byte.create sz) endi e
  | Restrict ({id=_; name; size; info=_}, {lo;hi}) -> Dba.Expr.restrict lo hi (Dba.Expr.var name size)

