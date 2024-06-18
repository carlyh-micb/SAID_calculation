 Author: Steven Mugisha Mizero, <smugisha@uoguelph.ca>

A `said` (Self-Addressing Identifier) - a special type of content-addressable identifier based on encoded cryptographic digest that is self-referential.

- SAIDs facilitates immutably referenced data serialization for applications such as [Verifiable Credentials](https://en.wikipedia.org/wiki/Verifiable_credentials) or [Ricardian Contracts](https://en.wikipedia.org/wiki/Ricardian_contract).

#### `said` [Generation and Verification Protocols](https://www.ietf.org/archive/id/draft-ssmith-said-03.html#section-2.3)
---
- `saids` are encoded with CESR (Composable Event Stream Representation) [CESR](https://datatracker.ietf.org/doc/draft-ssmith-cesr/) which includes cryptographic algorithms used to generate the digest.
##### A simple example of a `said` generation:
- The CESR encoding used is a Blake3-256 (32 bytes) binary digest which has 44 Base-64 URL-safe characters - the first character is **E** representing Blake3-256.

Step 1: **Fill the field to hold the `said` with 44 of # characters length.**

`field0______field1______________________________________field2______`

`field0______############################################field2______`

Step 2: **Compute the Blake3-256 digest on the above serialized string and encoded in CESR format.** 

Results in the below `said`:

`E8wYuBjhslETYaLZcxMkWrhVbMcA8RS1pKYl7nJ77ntA`

Step 3: **Replace the dummy `#` with the produced `said` - the final serialization will include an embedded `said` as follows:**

`field0______E8wYuBjhslETYaLZcxMkWrhVbMcA8RS1pKYl7nJ77ntA______`


> [!Warning] Order-Preserving Data Structures
> The  crucial consideration in `said` generation is reproducibility.

- `said` generation to be reproducibly requires the ordering and sizing of fields to be fixed.
- The essential feature needed for reproducible serialization of mappings (dictionaries or hash tables) is that mapping preserve the ordering of its fields on any round trip to/from a serialization.
- The natural canonical order of data structures like a hash table or dictionary is the insertion order of the fields allowing them to appear in a present order independent of the **lexicographic ordering** **of the labels**.
- A way to describe a predefined order preserving serialization is **canonicalization** or **canonical ordering**. This affects the functional perspective of ordering fields as they are sorted by labels prior to serialization.
- Hash tables such `defaultdict` in `python`, the new `ECMAScript` introducing `Reflect.ownPropertyKeys()`, and the version 1.9 of `Ruby` with `Hash class` do preserve insertion order of the fields. Thus there is no need of any **canonical serialization**, one can rely on natural insertion order of the mappings to preserve the functional logic or can always opt for lexicographic ordering to create the insertion order.

#### `said` verification protocol:
1.  Make a copy of the embedded CESR encoded SAID string included in the serialization. 
2. Replace the SAID field value in the serialization with a dummy string of the same length. The dummy character is #, that is, ASCII 35 decimal (23 hex). 
3. Compute the digest of the serialization that includes the dummy value for the SAID field. Use the digest algorithm specified by the CESR  derivation code of the copied SAID. 
4. Encode the computed digest with CESR   to create the final derived and encoded SAID of the same total length as the dummy string and the copied embedded SAID. 
5. Compare the copied SAID with the recomputed SAID. If they are identical then the verification is successful; otherwise, unsuccessful.


##### Steps  for generating a `said`  using a `python dict` 
---
1. Initial `dict` before serialization.

``` Python
{
    "said": "",
    "first": "Sue",
    "last": "Smith",
    "role": "Founder"
}
```

2. `said` key will contain an encoded `CESR Blake3-256` digest of 44 characters. Initialized with a total of 44 #.

``` Python
{
    "said": "############################################",
    "first": "Sue",
    "last": "Smith",
    "role": "Founder"
}
```

3. The `dict` serialized into `json` with no extra whitespace:
`{"said":"############################################","first":"Sue","last":"Smith","role":"Founder"}.

4. The Blake3-256 digest is then computed on that serialized `json`:

`said`: `EnKa0ALimLL8eQdZGzglJG_SxvncxkmvwFDhIyLFchUk`

5. The final serialization with the `said` embedded as follows:
`{"said":"EnKa0ALimLL8eQdZGzglJG_SxvncxkmvwFDhIyLFchUk","first":"Sue","last":"Smith","role":"Founder"}


> [!Note] Preserving Order
> The generation steps may be reversed to verify the embedded `said` following the verification protocol defined above. However, to achieve consistency `said` generation and verification protocol for mapping assumes that the fields in a mapping serialization such as `json` are ordered in a stable, and reproducible order, i.e., canonical.

##### The Human Colossus Lab ([HCF](https://humancolossus.foundation/)) [`said`](https://github.com/THCLab/cesrox/tree/master/said) implementation in `rust`
---
The below section summarizes the work done by HCF to compute `saids`. The emphasis is to understand the `SAD` macro that contains the under hood functionalities allowing the manipulation of RUST AST of an object (i.e., a `struct`) to place the computed digest inside the `struct` it was calculated on. But again we want the clarity of what happens when you write an OCAFILE and get an OCA bundle that has a `said` and each overlay containing individual `said`.


*click link to see the image.* 
[oca-image.png](https://uoguelphca-my.sharepoint.com/:i:/g/personal/smugisha_uoguelph_ca/EYeU54Z6waJHicSFfOZr9CgB-4HrRw5h06kpaC1NFAkHXA?e=4OZx4S)

In summary when a user writes an `oca file` instructions such as `add` ,  `remove`  or `from` they dictate what the `oca ast` represents. From the above picture only one attribute `test` is added. `oca-bundle` builds from the generated `oca ast`  putting the AST parts together to form a defined overlay is there is. In the example only the `capture_base` is built. Each overlay same as the capture base are structs that implements `SAD` macro that will be discussed in the next sections. After the digest is computed for an overlay the `capture base` `said` is added to it and the digest of the whole bundle is the computed on top and inserted. 


The following highlights a high level description of what you achieve with crates developed b the HCF to calculate the digest. 

The following example shows a digest calculated for the string literal `hello there`.

``` Rust
let data = "hello there";
let code: HashFunction = HashFunctionCode::Blake3_256.into();
let sai = code.derive(data.as_bytes());

assert_eq!(format!("{}", sai), "ENmwqnqVxonf_bNZ0hMipOJJY25dxlC8eSY5BbyMCfLJ");
assert!(sai.verify_binding(data.as_bytes()));
assert!(!sai.verify_binding("wrong data".as_bytes()));
```

- Module `sad` provides trait `SAD` that has functions:
	- `compute_digest` : computes the `said` of a data structure, places it in a chosen field.
	- `derivation_data` : returns data that are used for `said` computation.

- To use the `SAD` macros it has to be enabled, and the user chooses the filed to be replaced by the computed digest. `SAD` only works for structures that implement `Serialize` using 
  `#[derive(Serialize)]` attribute, rather than a custom implementation.

- Attributes that `SAD` macro uses: 
	-  `version`: adds the version field while computing derivation data. Version string contains compact representation of **field map**, **serialization format**, and **size of a serialized message body**. Attribute let user specify protocol code and its major and minor version. When attribute is used, the structure automatically implements the `Encode` trait, which provides the `encode` function for serializing the element according to the chosen serialization format.
	
	-  `said` - this attribute allows users to choose the hash function for computing Self Addressing Identifier and serialization format. The hash function can be specified using the derivation code from the table above. The available serialization formats are `json`, `CBOR`, and `MGPK`. <u>By default, JSON and Blake3-256 are used.</u>

- Fields attributes: `said` - marks field that should be replaced by computed digest during `compute_digest`. 

Example of a `struct` that implements `SAD` Marco:

``` Rust
#[derive(SAD, Serialize)]
#[version(protocol = "KERI", major = 1, minor = 0)]
struct Something {
	pub text: String,
	#[said]
	pub d: Option<SelfAddressingIdentifier>,
}
```

- It is mandatory to annotate the field that will hold the computed digest with `#[said]`.

A [test example](https://github.com/THCLab/cesrox/blob/master/said/tests/sad_test.rs) demonstrating  `said` computation of the above `struct`.

``` Rust
#[cfg(feature = "macros")]
mod tests {
    use said::derivation::HashFunctionCode;
    use said::sad::SAD;
    use said::version::format::SerializationFormats;
    use said::SelfAddressingIdentifier;
    use serde::Serialize;

    #[test]
    pub fn basic_derive_test() {
        #[derive(SAD, Serialize)]
        struct Something {
            pub text: String,
            #[said]
            pub d: Option<SelfAddressingIdentifier>,
        }

        let mut something = Something {
            text: "Hello world".to_string(),
            d: None,
        };

        let code = HashFunctionCode::Blake3_256;
        let format = SerializationFormats::JSON;
        something.compute_digest(&code, &format);
        let computed_digest = something.d.as_ref();
        let derivation_data = something.derivation_data(&code, &format);

        assert_eq!(
            format!(
                r#"{{"text":"Hello world","d":"{}"}}"#,
                "############################################"
            ),
            String::from_utf8(derivation_data.clone()).unwrap()
        );

        assert_eq!(
            computed_digest,
            Some(
                &"EF-7wdNGXqgO4aoVxRpdWELCx_MkMMjx7aKg9sqzjKwI"
                    .parse()
                    .unwrap()
            )
        );
        assert!(something
            .d
            .as_ref()
            .unwrap()
            .verify_binding(&something.derivation_data(&code, &format)));
    }
}```

Part I: 
 - [Derivation crate](https://github.com/THCLab/cesrox/tree/master/said/src/derivation)  - `use said::derivation::HashFunctionCode`, wraps the possible hash functions supported by [CESROX](https://github.com/THCLab/cesrox/tree/master/cesr). i.e.; in the above code snippet `Blake3_256` is used.
 - [Version crate](https://github.com/THCLab/cesrox/tree/master/said/src/version) `use said::version::format::SerializationFormats`, this crate allow a users to retrieve the serialization format. i.e.; in the above code snippet `JSON` is used.
 - [SAD crate](https://github.com/THCLab/cesrox/tree/master/said/src/sad) `use said::sad::SAD` defines the `trait` with two functions `compute_digest` and `derivation_data` which are implemented using **Procedural Macros**. 
 - [SelfAddressingIdentifier](https://github.com/THCLab/cesrox/blob/master/said/src/lib.rs) `use said::SelfAddressingIdentifier` defines a struct with `derivation: HashFunction` and `digest: Vec<u8>` as the fields. 
- `use serde::Serialize` a standard Serialize crate.

Part II:

```Rust
let mut something = Something {
	text: "Hello world".to_string(),
	d: None,
};
```

- `A struct` with only two fields `text` (which can be anything, it can also be a struct) and `d` (the computed said will be held here).


- The below five lines of code computes the digest and places it inside `something` struct where it is assigned to the field `d`.
```Rust
let code = HashFunctionCode::Blake3_256;
let format = SerializationFormats::JSON;
something.compute_digest(&code, &format);
let computed_digest = something.d.as_ref();
let derivation_data = something.derivation_data(&code, &format);
```

- Annotating `Something` struct with `#[derive(SAD, Serialize)]` allows to use the `computed_digest` function defined in the `SAD` crate and implemented under `SAD` Macros to be applied on it and compute the digest, and does all the background process of replacing `None` with the hash.
- `let derivation_data = something.derivation_data(&code, &format)` this line serializes the struct and replaces the field to hold the hash with #.

Part III:
`assert_eq!` and `assert!` are used to the output of the functions.

#### `SAD` Marco In-depth
----
This section goes one level deeper and explains how we achieve the placement of the computed digest inside the `struct` it was initially computed on.

How does Rust allow manipulating a `struct`:
- Rust provides [Procedural macros](https://doc.rust-lang.org/reference/procedural-macros.html) feature that allows to manipulate the a struct's Rust AST leveraging the power of accepting some code as an input, operate on that code, and produce some code as an output.
- With this concept we can define a function that takes a struct's Rust AST and do some changes with it (replacing # with a computed digest) and then return an other struct's Rust AST with the `said` embedded.

For more in-depth about Procedural Macros take a look at a simple practical example [here](https://www.youtube.com/watch?v=XY0yR6IPbhw&ab_channel=Schr%C3%B6dinger%27sWatermelon) or refer to this documentation [here](https://doc.rust-lang.org/book/ch19-06-macros.html) for more beginner friendly introduction to Procedural Macros concepts.

#### This is how the [HCF](https://github.com/THCLab) computes `said` using **Procedural Macros**:

>[!Note] why `SAD` macro?
>Starting with the `sad` trait which implements two functions: `compute_digest` and `derivation_data`. A `SAD` macro is created to avoid structs to individually implementing these functions but rather depend on the `SAD` macro abstraction. For usability the `SAD` macro the structs have to be annotated with `#[derive](SAD)`, and implement `Serialize` trait. 

The below code snippet shows the `SAD` trait which can also be found  [here](https://github.com/THCLab/cesrox/tree/master/said/src/sad):

```Rust

// importing dependency crates
use crate::derivation::HashFunctionCode;
pub use crate::version::format::SerializationFormats;
pub use cesrox::derivation_code::DerivationCode;

#[cfg(feature = "macros")]
pub use sad_macros::SAD;

pub trait SAD {
    fn compute_digest(
	    &mut self,
	    derivation: &HashFunctionCode,
	    format: &SerializationFormats
	);

    fn derivation_data(
        &self,
        derivation: &HashFunctionCode,
        format: &SerializationFormats,
    ) -> Vec<u8>;
}
```

> [!Warning] SAD Macro

Similar to other Procedural Macros its start by defining the function that takes in a `TokenStream` and returns `TokenStream`. The `TokenStream` is generated by the Rust compiler and it is essentially a serialized version of the syntax tree of the annotated item, representing Rust code in a way that can be manipulated programmatically. 

```Rust

// importing dependecy crates
use field::TransField;
use proc_macro::TokenStream;
use quote::quote;
use syn::{self};

mod field;
mod version;
use version::parse_version_args;

#[proc_macro_derive(SAD, attributes(said, version))]
pub fn compute_digest_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_compute_digest(&ast)
}

```

**A simple example of using the `SAD` macro:**
```Rust
// Notice that we have added Serialize attribute to be able to use the macro
#[derive(SAD, Serialize)]
struct FirstStruct {
	#[said]
	d: None
}
```

- Here Rust compiler will call the Procedural Macro function `compute_digest_derive` passing the `TokenStream` representing `struct FirstStruct` as the argument. 
- Inside `compute_digest_derive` function, the `TokenStream` is parsed into a more usable AST using the [`syn` crate](https://jeltef.github.io/derive_more/syn/index.html) allowing the inspection and manipulation. 
- The `impl_computed_digest` function takes in a reference to Rust AST and returns Rust code as a  `TokenStream` representing the `FirstStruct` with the computed `digest` placed in (i.e., assigned to ).
- Finally the compiler takes the returned `TokenStream` and integrates it back into the compilation process, replacing the annotated `FirstStruct` with the `FirstStruct` generated by the `SAD` macro (i.e., the variable `d` holding the digest). 

As an example: the digest could be something like `E8wYuBjhslETYaLZcxMkWrhVbMcA8RS1pKYl7nJ77ntA`. Thus, the final struct might look like the below:

```Rust
struct FirstStruct {
	d: E8wYuBjhslETYaLZcxMkWrhVbMcA8RS1pKYl7nJ77ntA
}

```


**Implementation of `impl_computed_digest`:** 
```Rust
fn impl_compute_digest(ast: &syn::DeriveInput) -> TokenStream { }
```

This function hides all the manipulations of placing the computed digest inside a struct when annotated with `#[derive(SAD)]`, thus the name `said`.

- `syn` is an important library that parses a stream of Rust tokens into a syntax tree (AST) of Rust source code, it contains a few APIs that are generally useful, and `Derive` is the API particularly useful to derive Procedural Macros thus the `impl_compute_digest` function takes in a reference of `&syn::DeriveInput` (look at last page of this document to see how a `DeriveInput` AST look like).  To explore more about Rust AST use [AST Explorer](https://astexplorer.net/) and select Rust language.

The full code of the `imp_compute_digest` can be found [here](https://github.com/THCLab/cesrox/blob/master/said/sad_macros/src/lib.rs). The below is the dissection of the code to help understand how each part play a role in manipulating the structs annotated with `#[derive(SAD)]`.

N.B: There is less wording as the code are self explanatory the comments that were provided in the code provide the general idea of what the below chunk of codes does. 

Part I: 

```Rust
let name = &ast.ident;
let fname = format!("{}TMP", name);
let varname = syn::Ident::new(&fname, name.span());

let generics = &ast.generics;
let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

// Check if versioned attribute is added.
let version = ast
    .attrs
    .iter()
    .find(|attr| attr.path().is_ident("version"))
    .map(parse_version_args);

let fields = match &ast.data {
	syn::Data::Struct(s) => s.fields.clone(),
	_ => panic!("Not a struct"),
	}
	.into_iter()
	.map(TransField::from_ast);
```

The first part of the function includes the following:
- Grabs the name field the `struct` e.g `FirstStruct` and formats it and stores it under `varname`. 
- `let (impl_generics, ty_generics, where_clause) = generics.split_for_impl()` this lines gets the fields to manipulate in case the `struct` incudes generic types. To read more about generics in Rust click [here](https://doc.rust-lang.org/book/ch10-00-generics.html)
-  It is important to note that the `attrs` field under the `DeriveInput` AST includes other annotations if any provided by the `struct` (i.e., other traits that the `struct` implements). Thus if a struct is annotated with `#[version(protocol = "KERI", major = 1, minor = 0)]`, [`parse_version_args`](https://github.com/Steven-Mugisha/cesrox/blob/master/said/sad_macros/src/version.rs) function is used to return a well formatted version of the fields.
- The `data` field in `DeriveInput` AST contains all the fields defined in the a crate. Fields here are referred to as `structs` but they could also be `enums` that is why the code panic if no struct if found in the whole crate. 
	- The code snippet above uses a match statement to find all the structs  and map the fields into `TransField` defined [here](https://github.com/Steven-Mugisha/cesrox/blob/master/said/sad_macros/src/field.rs) . In short the function `from_ast` of  `TransField` struct inputs a type of `syn::Field` (which is part of the `DeriveInput`) as input and returns a transformed `TransField` struct. In other words, each struct is transformed to match the logic defined in the `TransField` implementation.

Part II: 

```Rust
// Generate body of newly created struct fields.
// Replace field type with String if it is tagged as said.
let body = fields.clone().map(|field| {
	if !field.said {
		let original = field.original;
        quote! {#original}
    } else {
	    let name = &field.name;
        let attrs = field.attributes;
        quote! {
	        #(#attrs)*
            #name: String
        }
    }
});
```

```Rust
// Set fields tagged as said to computed digest string, depending on
// digest set in `dig_length` variable. Needed for generation of From
// implementation.
let concrete = fields.clone().map(|field| {
	let name = &field.name;
	if field.said {
		quote! {#name: "#".repeat(dig_length).to_string()}
	} else {
		quote! {#name: value.#name.clone()}
	}
});
```

```Rust
// Set fields tagged as said to computed SAID set in `digest` variable.
let out = fields.map(|field| {
	let name = &field.name;
	if field.said {
		quote! {self.#name = digest.clone();}
	} else {
		quote! {}
	}
});
```

```Rust
// Adding version field logic.
let version_field = if version.is_some() {
	quote! {
	#[serde(rename = "v")]
	version: SerializationInfo,
	}
} else {
	quote! {}
};

// If version was set, implement Encode trait
let encode = if let Some((prot, major, minor)) = version.as_ref() {
	quote! {
			#[derive(Serialize)]
		struct Version<D> {
			v: SerializationInfo,
			#[serde(flatten)]
			d: D
		}
			use said::version::Encode;
			impl #impl_generics Encode for #name #ty_generics #where_clause {
				fn encode(&self, code: &HashFunctionCode, 
				format: &SerializationFormats) -> Result<Vec<u8>,
				said::version::error::Error> {
				let size = self.derivation_data(code, format).len();
				let v = SerializationInfo::new(#prot.to_string(),
				 #major, #minor, format.clone(), size);
				let versioned = Version {v, d: self.clone()};
				Ok(format.encode(&versioned).unwrap())
			}
		}
	}
} else {
	quote!()
};
```

-  N.B: the  macro [`quote!`](https://docs.rs/quote/latest/quote/) is used to turning Rust AST data structures into tokens of source code. 

- The Encode trait is found [here](https://github.com/THCLab/cesrox/blob/master/said/src/version/mod.rs), also its implementation is performed under `SAD` macro when the version is provided.
```Rust
pub trait Encode {
    fn encode(
        &self,
        code: &HashFunctionCode,
        serialization_format: &SerializationFormats,
    ) -> Result<Vec<u8>, Error>;
}
```

Part III:

```Rust

// Creates a temporarily struct that has a well formatted version variable and copying the concrete part of the struct defined in part II.
let tmp_struct = if let Some((prot, major, minor)) = version {
	quote! {
	   let mut tmp_self = Self {
	   version: SerializationInfo::new_empty(#prot.to_string(),
	    #major, #minor, SerializationFormats::JSON),
	    #(#concrete,)*
	    };
		let enc = tmp_self.version.serialize(&tmp_self).unwrap();
		tmp_self.version.size = enc.len();
		tmp_self
	}
} else {
	quote! {Self {
		#(#concrete,)*
	}}
};

```

```Rust

let gen = quote! {
// Create temporary, serializable struct and implements the compute_digest and derivation_data on the newly generate struct.
#[derive(Serialize)]
struct #varname #ty_generics #where_clause {
	#version_field
	#(#body,)*
}

#encode

impl #impl_generics From<(&#name #ty_generics, usize)> for #varname #ty_generics #where_clause {
	fn from(value: (&#name #ty_generics, usize)) -> Self {
		let dig_length = value.1;

		let value = value.0;
		#tmp_struct
	}
}

impl #impl_generics SAD for #name #ty_generics #where_clause {
	fn compute_digest(&mut self, code: &HashFunctionCode, 
	format: &SerializationFormats ) {
		use said::derivation::{HashFunctionCode, HashFunction};
		let serialized = self.derivation_data(code, format);
		let digest = Some(HashFunction::from(code.clone()).derive(&serialized));
		#(#out;)*
	}

	fn derivation_data(&self, code: &HashFunctionCode, 
	serialization_format: &SerializationFormats) -> Vec<u8> {
		use said::derivation::HashFunctionCode;
		use said::sad::DerivationCode;
		let tmp: #varname #ty_generics = (self, code.full_size()).into();
		serialization_format.encode(&tmp).unwrap()
	}
};
};
gen.into()
```


#### References
---
1. https://www.ietf.org/archive/id/draft-ssmith-said-03.html#name-appendix-embedding-saids-in
2. https://github.com/THCLab/cesrox/tree/master/said
3. https://snyk.io/advisor/npm-package/self-addressing-identifier

#### Supplementary

This is the `DeriveInput` AST for the below struct:

```Rust
#[derive(SAD, Serialize)]
struct Something {
	pub text: String,
	#[said]
	pub d: Option<SelfAddressingIdentifier>,
}

```


```String
DeriveInput {
    attrs: [],
    vis: Visibility::Inherited,
    ident: Ident {
        ident: "Something",
        span: #0 bytes(321..330),
    },
    generics: Generics {
        lt_token: None,
        params: [],
        gt_token: None,
        where_clause: None,
    },
    data: Data::Struct {
        struct_token: Struct,
        fields: Fields::Named {
            brace_token: Brace,
            named: [
                Field {
                    attrs: [],
                    vis: Visibility::Public(
                        Pub,
                    ),
                    mutability: FieldMutability::None,
                    ident: Some(
                        Ident {
                            ident: "text",
                            span: #0 bytes(349..353),
                        },
                    ),
                    colon_token: Some(
                        Colon,
                    ),
                    ty: Type::Path {
                        qself: None,
                        path: Path {
                            leading_colon: None,
                            segments: [
                                PathSegment {
                                    ident: Ident {
                                        ident: "String",
                                        span: #0 bytes(355..361),
                                    },
                                    arguments: PathArguments::None,
                                },
                            ],
                        },
                    },
                },
                Comma,
                Field {
                    attrs: [
                        Attribute {
                            pound_token: Pound,
                            style: AttrStyle::Outer,
                            bracket_token: Bracket,
                            meta: Meta::Path {
                                leading_colon: None,
                                segments: [
                                    PathSegment {
                                        ident: Ident {
                                            ident: "said",
                                            span: #0 bytes(377..381),
                                        },
                                        arguments: PathArguments::None,
                                    },
                                ],
                            },
                        },
                    ],
                    vis: Visibility::Public(
                        Pub,
                    ),
                    mutability: FieldMutability::None,
                    ident: Some(
                        Ident {
                            ident: "d",
                            span: #0 bytes(399..400),
                        },
                    ),
                    colon_token: Some(
                        Colon,
                    ),
                    ty: Type::Path {
                        qself: None,
                        path: Path {
                            leading_colon: None,
                            segments: [
                                PathSegment {
                                    ident: Ident {
                                        ident: "Option",
                                        span: #0 bytes(402..408),
                                    },
                                    arguments: PathArguments::AngleBracketed {
                                        colon2_token: None,
                                        lt_token: Lt,
                                        args: [
                                            GenericArgument::Type(
                                                Type::Path {
                                                    qself: None,
                                                    path: Path {
                                                        leading_colon: None,
                                                        segments: [
                                                            PathSegment {
                                                                ident: Ident {
                                                                    ident:
													"SelfAddressingIdentifier",
                                                                    span: #0 
                                                                bytes(409..433),
                                                                },
                                                                arguments:
                                                             PathArguments::None,
                                                            },
                                                        ],
                                                    },
                                                },
                                            ),
                                        ],
                                        gt_token: Gt,
                                    },
                                },
                            ],
                        },
                    },
                },
                Comma,
            ],
        },
        semi_token: None,
    },
}
```
