                // Use enhanced validation for the output file path
                validation_enhanced::validate_output_file_path(output_path)
                    .map_err(|e| OxideScannerError::config(format!("Invalid output file path: {}", e)))?;

                return Ok(Some(output_path.clone()));