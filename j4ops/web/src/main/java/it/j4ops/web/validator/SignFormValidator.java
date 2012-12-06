package it.j4ops.web.validator;


import it.j4ops.web.model.SignForm;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

public class SignFormValidator implements Validator {

    @Override
    public boolean supports(Class<?> clazz) {
        return (SignForm.class).isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object obj, Errors errors) {

        SignForm signForm = (SignForm) obj;
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "signType", "field.required", "SignType is required field");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "addSignInfo", "field.required", "AddSignInfo is required field");
    }
}
