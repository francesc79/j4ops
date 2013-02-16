package it.j4ops.web.validator;


import it.j4ops.web.model.Sign;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

public class SignFormValidator implements Validator {

    @Override
    public boolean supports(Class<?> clazz) {
        return (Sign.class).isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object obj, Errors errors) {

        Sign sign = (Sign) obj;
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "envelopeSignType", "field.required", "EnvelopeSignType is required field");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "signMode", "field.required", "SignMode is required field");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "xmlSignMode", "field.required", "XmlSignMode is required field");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "addSignInfo", "field.required", "AddSignInfo is required field");
    }
}
