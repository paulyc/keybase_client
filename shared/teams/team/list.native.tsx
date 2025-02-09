import * as React from 'react'
import {NativeSectionList} from '../../common-adapters/mobile.native'
import {Props} from './list'
import {globalStyles} from '../../styles'

type State = {
  sections: Array<any>
}

class List extends React.Component<Props, State> {
  _renderSectionHeader = ({section}) => (section.key === 'body' ? this.props.renderRow(section.header) : null)
  _renderRow = data => this.props.renderRow(data.item)

  render() {
    const rows = this.props.rows || []
    const sections = [
      {
        data: rows.slice(0, 1),
        key: 'header',
      },
      {
        data: rows.slice(2),
        header: rows[1],
        key: 'body',
      },
    ]
    return (
      <NativeSectionList
        alwaysBounceVertical={false}
        renderItem={this._renderRow}
        renderSectionHeader={this._renderSectionHeader}
        stickySectionHeadersEnabled={true}
        sections={sections}
        style={listStyle}
        contentContainerStyle={contentContainerStyle}
      />
    )
  }
}

const listStyle = globalStyles.fillAbsolute

const contentContainerStyle = {
  display: 'flex',
  flexGrow: 1,
}

export default List
