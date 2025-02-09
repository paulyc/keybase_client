import * as React from 'react'
import * as Sb from '../../stories/storybook'
import {storyDecorator} from '../common-stories'
import EnterEmail from '.'

const props = {
  allowSearch: false,
  onChangeAllowSearch: Sb.action('onChangeAllowSearch'),
  onChangeEmail: Sb.action('onChangeEmail'),
  onFinish: Sb.action('onFinish'),
  onSkip: Sb.action('onSkip'),
}

const load = () => {
  Sb.storiesOf('New signup', module)
    .addDecorator(storyDecorator)
    .add('Enter email', () => <EnterEmail {...props} />)
}

export default load
