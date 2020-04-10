// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.

// Note that source_map_mappings requires 0-indexed line and column numbers but
// V8 Exceptions are 1-indexed.

// TODO: This currently only applies to uncaught exceptions. It would be nice to
// also have source maps for situations like this:
//   const err = new Error("Boo!");
//   console.log(err.stack);
// It would require calling into Rust from Error.prototype.prepareStackTrace.

use crate::ErrBox;
use rusty_v8 as v8;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::error::Error;
use std::fmt;

/// A `JSError` represents an exception coming from V8, with stack frames and
/// line numbers. The deno_cli crate defines another `JSError` type, which wraps
/// the one defined here, that adds source map support and colorful formatting.
#[derive(Debug, PartialEq, Clone)]
pub struct JSError {
  pub message: String,
  pub source_line: Option<String>,
  pub script_resource_name: Option<String>,
  pub line_number: Option<i64>,
  pub start_column: Option<i64>,
  pub end_column: Option<i64>,
  pub frames: Vec<JSStackFrame>,
  // TODO: Remove this field. It is required because JSError::from_v8_exception
  // will generally (but not always) return stack frames passed from
  // `prepareStackTrace()` which have already been source-mapped, and we need a
  // flag saying not to do it again. Note: applies to `frames` but not
  // `source_line`.
  pub already_source_mapped: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct JSStackFrame {
  pub line_number: i64, // zero indexed
  pub column: i64,      // zero indexed
  pub script_name: String,
  pub function_name: String,
  pub is_eval: bool,
  pub is_constructor: bool,
  pub is_async: bool,
  // TODO(nayeemrmn): Support more CallSite fields.
}

fn get_property<'a>(
  scope: &mut impl v8::ToLocal<'a>,
  context: v8::Local<v8::Context>,
  object: v8::Local<v8::Object>,
  key: &str,
) -> Option<v8::Local<'a, v8::Value>> {
  let key = v8::String::new(scope, key).unwrap();
  object.get(scope, context, key.into())
}

impl JSError {
  pub(crate) fn create(js_error: Self) -> ErrBox {
    ErrBox::from(js_error)
  }

  pub fn from_v8_exception(
    scope: &mut impl v8::InIsolate,
    exception: v8::Local<v8::Value>,
  ) -> Self {
    // Create a new HandleScope because we're creating a lot of new local
    // handles below.
    let mut hs = v8::HandleScope::new(scope);
    let scope = hs.enter();
    let context = { scope.get_current_context().unwrap() };

    let msg = v8::Exception::create_message(scope, exception);

    let exception: Option<v8::Local<v8::Object>> =
      exception.clone().try_into().ok();
    let _ = exception.map(|e| get_property(scope, context, e, "stack"));

    let maybe_call_sites = exception
      .and_then(|e| get_property(scope, context, e, "__callSiteEvals"));
    let maybe_call_sites: Option<v8::Local<v8::Array>> =
      maybe_call_sites.and_then(|a| a.try_into().ok());

    let already_source_mapped;
    let frames = if let Some(call_sites) = maybe_call_sites {
      already_source_mapped = true;
      let mut output: Vec<JSStackFrame> = vec![];
      for i in 0..call_sites.length() {
        let call_site: v8::Local<v8::Object> = call_sites
          .get_index(scope, context, i)
          .unwrap()
          .try_into()
          .unwrap();
        let line_number: v8::Local<v8::Integer> =
          get_property(scope, context, call_site, "lineNumber")
            .unwrap()
            .try_into()
            .unwrap();
        let line_number = line_number.value() - 1;
        let column_number: v8::Local<v8::Integer> =
          get_property(scope, context, call_site, "columnNumber")
            .unwrap()
            .try_into()
            .unwrap();
        let column_number = column_number.value() - 1;
        let file_name: Result<v8::Local<v8::String>, _> =
          get_property(scope, context, call_site, "fileName")
            .unwrap()
            .try_into();
        let file_name = file_name
          .map_or_else(|_| String::new(), |s| s.to_rust_string_lossy(scope));
        let function_name: Result<v8::Local<v8::String>, _> =
          get_property(scope, context, call_site, "functionName")
            .unwrap()
            .try_into();
        let function_name = function_name
          .map_or_else(|_| String::new(), |s| s.to_rust_string_lossy(scope));
        let is_constructor: v8::Local<v8::Boolean> =
          get_property(scope, context, call_site, "isConstructor")
            .unwrap()
            .try_into()
            .unwrap();
        let is_constructor = is_constructor.is_true();
        let is_eval: v8::Local<v8::Boolean> =
          get_property(scope, context, call_site, "isEval")
            .unwrap()
            .try_into()
            .unwrap();
        let is_eval = is_eval.is_true();
        let is_async: v8::Local<v8::Boolean> =
          get_property(scope, context, call_site, "isAsync")
            .unwrap()
            .try_into()
            .unwrap();
        let is_async = is_async.is_true();
        output.push(JSStackFrame {
          line_number,
          column: column_number,
          script_name: file_name,
          function_name,
          is_constructor,
          is_eval,
          is_async,
        });
      }
      output
    } else {
      already_source_mapped = false;
      msg
        .get_stack_trace(scope)
        .map(|stack_trace| {
          (0..stack_trace.get_frame_count())
            .map(|i| {
              let frame = stack_trace.get_frame(scope, i).unwrap();
              JSStackFrame {
                line_number: frame
                  .get_line_number()
                  .checked_sub(1)
                  .and_then(|v| v.try_into().ok())
                  .unwrap(),
                column: frame
                  .get_column()
                  .checked_sub(1)
                  .and_then(|v| v.try_into().ok())
                  .unwrap(),
                script_name: frame
                  .get_script_name_or_source_url(scope)
                  .map(|v| v.to_rust_string_lossy(scope))
                  .unwrap_or_else(|| "<unknown>".to_owned()),
                function_name: frame
                  .get_function_name(scope)
                  .map(|v| v.to_rust_string_lossy(scope))
                  .unwrap_or_else(|| "".to_owned()),
                is_constructor: frame.is_constructor(),
                is_eval: frame.is_eval(),
                is_async: false,
              }
            })
            .collect::<Vec<_>>()
        })
        .unwrap_or_else(Vec::<_>::new)
    };

    Self {
      message: msg.get(scope).to_rust_string_lossy(scope),
      script_resource_name: msg
        .get_script_resource_name(scope)
        .and_then(|v| v8::Local::<v8::String>::try_from(v).ok())
        .map(|v| v.to_rust_string_lossy(scope)),
      source_line: msg
        .get_source_line(scope, context)
        .map(|v| v.to_rust_string_lossy(scope)),
      line_number: msg.get_line_number(context).and_then(|v| v.try_into().ok()),
      start_column: msg.get_start_column().try_into().ok(),
      end_column: msg.get_end_column().try_into().ok(),
      frames,
      already_source_mapped,
    }
  }
}

impl Error for JSError {}

fn format_source_loc(
  script_name: &str,
  line_number: i64,
  column: i64,
) -> String {
  // TODO match this style with how typescript displays errors.
  let line_number = line_number + 1;
  let column = column + 1;
  format!("{}:{}:{}", script_name, line_number, column)
}

fn format_stack_frame(frame: &JSStackFrame) -> String {
  // Note when we print to string, we change from 0-indexed to 1-indexed.
  let source_loc =
    format_source_loc(&frame.script_name, frame.line_number, frame.column);

  if !frame.function_name.is_empty() {
    format!("    at {} ({})", frame.function_name, source_loc)
  } else if frame.is_eval {
    format!("    at eval ({})", source_loc)
  } else if frame.is_async {
    format!("    at async ({})", source_loc)
  } else {
    format!("    at {}", source_loc)
  }
}

impl fmt::Display for JSError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    if self.script_resource_name.is_some() {
      let script_resource_name = self.script_resource_name.as_ref().unwrap();
      if self.line_number.is_some() && self.start_column.is_some() {
        assert!(self.line_number.is_some());
        assert!(self.start_column.is_some());
        let source_loc = format_source_loc(
          script_resource_name,
          self.line_number.unwrap() - 1,
          self.start_column.unwrap() - 1,
        );
        write!(f, "{}", source_loc)?;
      }
      if self.source_line.is_some() {
        write!(f, "\n{}\n", self.source_line.as_ref().unwrap())?;
        let mut s = String::new();
        for i in 0..self.end_column.unwrap() {
          if i >= self.start_column.unwrap() {
            s.push('^');
          } else {
            s.push(' ');
          }
        }
        writeln!(f, "{}", s)?;
      }
    }

    write!(f, "{}", self.message)?;

    for frame in &self.frames {
      write!(f, "\n{}", format_stack_frame(frame))?;
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn js_error_to_string() {
    let js_error = JSError {
      message: "Error: foo bar".to_string(),
      source_line: None,
      script_resource_name: None,
      line_number: None,
      start_column: None,
      end_column: None,
      frames: vec![
        JSStackFrame {
          line_number: 4,
          column: 16,
          script_name: "foo_bar.ts".to_string(),
          function_name: "foo".to_string(),
          is_eval: false,
          is_constructor: false,
          is_async: false,
        },
        JSStackFrame {
          line_number: 5,
          column: 20,
          script_name: "bar_baz.ts".to_string(),
          function_name: "qat".to_string(),
          is_eval: false,
          is_constructor: false,
          is_async: false,
        },
        JSStackFrame {
          line_number: 1,
          column: 1,
          script_name: "deno_main.js".to_string(),
          function_name: "".to_string(),
          is_eval: false,
          is_constructor: false,
          is_async: false,
        },
      ],
      already_source_mapped: true,
    };
    let actual = js_error.to_string();
    let expected = "Error: foo bar\n    at foo (foo_bar.ts:5:17)\n    at qat (bar_baz.ts:6:21)\n    at deno_main.js:2:2";
    assert_eq!(actual, expected);
  }
}
