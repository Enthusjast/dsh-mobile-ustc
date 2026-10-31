package cn.edu.ustc.dsh.mobile

import androidx.compose.ui.text.input.TextFieldValue

internal fun LoginController.editFixtureComposer(text: String, mode: String = "queue") {
    val current = requireNotNull(state.value.composer)
    editComposer(current.copy(value = TextFieldValue(text), mode = mode))
}

internal fun LoginController.submitFixtureMessage(mode: String, text: String, sendNow: Boolean = true) {
    editFixtureComposer(text, mode)
    submitMessage(MessageSubmission(requireNotNull(state.value.composer), sendNow))
}

internal fun LoginController.pickFixtureDocument(resume: String?, text: String, mode: String) {
    editFixtureComposer(text, mode)
    pickDocument(resume)
}
